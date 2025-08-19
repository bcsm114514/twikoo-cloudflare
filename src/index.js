/*!
 * Twikoo Cloudflare worker
 * (c) 2024-present Tao Xin & Mingy & iMaeGoo
 * Released under the MIT License.
 */

import { v4 as uuidv4 } from 'uuid' // 用户 id 生成
import xss from 'xss'
import {
  getCheerio,
  getMd5,
  getSha256,
  getXml2js,
  setCustomLibs
} from 'twikoo-func/utils/lib'
import {
  getFuncVersion,
  parseComment,
  normalizeMail,
  equalsMail,
  getMailMd5,
  getAvatar,
  isQQ,
  addQQMailSuffix,
  getQQAvatar,
  getPasswordStatus,
  preCheckSpam,
  getConfig,
  getConfigForAdmin,
  validate
} from 'twikoo-func/utils'
import {
  jsonParse,
  commentImportValine,
  commentImportDisqus,
  commentImportArtalk,
  commentImportArtalk2,
  commentImportTwikoo
} from 'twikoo-func/utils/import'
import { postCheckSpam } from 'twikoo-func/utils/spam'
import { sendNotice, emailTest } from 'twikoo-func/utils/notify'
import { uploadImage } from 'twikoo-func/utils/image'
import logger from 'twikoo-func/utils/logger'

// 常量 / constants
import constants from 'twikoo-func/utils/constants'

// 注入Cloudflare特定的依赖（原依赖于Cloudflare不兼容）
setCustomLibs({
  DOMPurify: {
    sanitize (input) {
      return input
    }
  },

  nodemailer: {
    createTransport (config) {
      return {
        verify () {
          if (!config.service || (config.service.toLowerCase() !== 'sendgrid' && config.service.toLowerCase() !== 'mailchannels')) {
            throw new Error('仅支持 SendGrid 和 MailChannels 邮件服务。')
          }
          if (!config.auth || !config.auth.user) {
            throw new Error('需要在 SMTP_USER 中配置账户名，如果邮件服务不需要可随意填写。')
          }
          if (!config.auth || !config.auth.pass) {
            throw new Error('需要在 SMTP_PASS 中配置 API 令牌。')
          }
          return true
        },

        sendMail ({ from, to, subject, html }) {
          if (config.service.toLowerCase() === 'sendgrid') {
            return fetch('https://api.sendgrid.com/v3/mail/send', {
              method: 'POST',
              headers: {
                'Authorization': `Bearer ${config.auth.pass}`,
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                personalizations: [{ to: [{ email: to }] }],
                from: { email: from },
                subject,
                content: [{ type: 'text/html', value: html }],
              })
            })
          } else if (config.service.toLowerCase() === 'mailchannels') {
            return fetch('https://api.mailchannels.net/tx/v1/send', {
              method: 'POST',
              headers: {
                'X-Api-Key': config.auth.pass,
                'Accept': 'application/json',
                'Content-Type': 'application/json',
              },
              body: JSON.stringify({
                personalizations: [{ to: [{ email: to }] }],
                from: { email: from },
                subject,
                content: [{ type: 'text/html', value: html }],
              })
            })
          }
        }
      }
    }
  }
})

const $ = getCheerio()
const md5 = getMd5()
const sha256 = getSha256()
const xml2js = getXml2js()

const { RES_CODE, MAX_REQUEST_TIMES } = constants
const VERSION = '1.6.40'

// 全局变量 / variables
let config
let accessToken
const requestTimes = {}

class DBBinding {
  constructor (binding) {
    this.DB = binding
  }

  get commentCountQuery () {
    return this._commentCountQuery ?? (this._commentCountQuery = this.DB.prepare(`
SELECT COUNT(*) AS count FROM comment
WHERE url = ?1 AND rid = "" AND (isSpam != ?2 OR uid = ?3)
`.trim()))
  }

  get commentQuery () {
    return this._commentQuery ?? (this._commentQuery = this.DB.prepare(`
SELECT * FROM comment
WHERE
  url = ?1 AND
  (isSpam != ?2 OR uid = ?3) AND
  created < ?4 AND
  top = ?5 AND
  rid = ""
ORDER BY created DESC
LIMIT ?6
`.trim()))
  }

  static replyQueryTemplate = `
SELECT * FROM comment
WHERE
  url = ?1 AND
  (isSpam != ?2 OR uid = ?3) AND
  rid IN ({{RIDS}})
`.trim()

  getReplyQuery (numParams) {
    if (!this.replyQueryCache) this.replyQueryCache = new Map()
    const cached = this.replyQueryCache.get(numParams)
    if (cached) return cached
    const result = this.DB.prepare(DBBinding.replyQueryTemplate.replace(
      '{{RIDS}}',	new Array(numParams).fill('?').join(', ')))
    this.replyQueryCache.set(numParams, result)
    return result
  }

  get commentForAdminCountQuery () {
    return this._commentForAdminCountQuery ?? (this._commentForAdminCountQuery = this.DB.prepare(`
SELECT COUNT(*) AS count FROM comment
WHERE
  isSpam != ?1 AND
  (nick LIKE ?2 OR
  mail LIKE ?2 OR
  link LIKE ?2 OR
  ip LIKE ?2 OR
  comment LIKE ?2 OR
  url LIKE ?2 OR
  href LIKE ?2)
`.trim()))
  }

  get commentForAdminQuery () {
    return this._commentForAdminQuery ?? (this._commentForAdminQuery = this.DB.prepare(`
SELECT * FROM comment
WHERE
  isSpam != ?1 AND
  (nick LIKE ?2 OR
  mail LIKE ?2 OR
  link LIKE ?2 OR
  ip LIKE ?2 OR
  comment LIKE ?2 OR
  url LIKE ?2 OR
  href LIKE ?2)
  ORDER BY created DESC
  LIMIT ?3 OFFSET ?4
`.trim()))
  }

  static commentSetStmtTemplate = `
UPDATE comment
SET {{FIELDS}}
WHERE _id = ?
`.trim()

  getCommentSetStmt (fields) {
    if (!this.commentSetStmtCache) this.commentSetStmtCache = new Map()
    const cacheKey = JSON.stringify(fields)
    const cached = this.commentSetStmtCache.get(cacheKey)
    if (cached) return cached
    const result = this.DB.prepare(DBBinding.commentSetStmtTemplate.replace(
      '{{FIELDS}}', fields.map(field => `${field} = ?`).join(', ')
    ))
    this.commentSetStmtCache.set(cacheKey, result)
    return result
  }

  get commentDeleteStmt () {
    return this._commentDeleteStmt ?? (this._commentDeleteStmt =
      this.DB.prepare('DELETE FROM comment WHERE _id = ?1')
    )
  }

  get commentExportQuery () {
    return this._commentExportQuery ?? (this._commentExportQuery =
      this.DB.prepare('SELECT * FROM comment')
    )
  }

  get commentByIdQuery () {
    return this._commentByIdQuery ?? (this._commentByIdQuery =
      this.DB.prepare('SELECT * FROM comment WHERE _id = ?1')
    )
  }

  get updateLikeStmt () {
    return this._updateLikeStmt ?? (this._updateLikeStmt =
      this.DB.prepare('UPDATE comment SET like = ?2 WHERE _id = ?1')
    )
  }

  get saveCommentStmt () {
    return this._saveCommentStmt ?? (this._saveCommentStmt =
      this.DB.prepare(`
INSERT INTO comment VALUES (
  ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
  ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20
)
`.trim()))
  }

  get commentCountSinceByIpQuery () {
    return this._commentCountSinceByIpQuery ?? (this._commentCountSinceByIpQuery = this.DB.prepare(`
SELECT COUNT(*) AS count FROM comment
WHERE created > ?1 AND ip = ?2
`.trim()))
  }

  get commentCountSinceQuery () {
    return this._commentCountSinceQuery ?? (this._commentCountSinceQuery = this.DB.prepare(`
SELECT COUNT(*) AS count FROM comment
WHERE created > ?1
`.trim()))
  }

  get updateIsSpamStmt () {
    return this._updateIsSpamStmt ?? (this._updateIsSpamStmt = this.DB.prepare(`
UPDATE comment SET isSpam = ?2, updated = ?3 WHERE _id = ?1
`.trim()))
  }

  get incCounterStmt () {
    return this._incCounterStmt ?? (this._incCounterStmt = this.DB.prepare(`
INSERT INTO counter VALUES
(?1, ?2, 1, ?3, ?3)
ON CONFLICT (url) DO UPDATE SET time = time + 1, title = ?2, updated = ?3
`.trim()))
  }

  get counterQuery () {
    return this._counterQuery ?? (this._counterQuery =
      this.DB.prepare('SELECT time FROM counter WHERE url = ?1')
    )
  }

  get commentCountByUrlQuery () {
    return this._commentCountByUrlQuery ?? (this._commentCountByUrlQuery = this.DB.prepare(`
SELECT COUNT(*) AS count FROM comment
WHERE url = ?1 AND NOT isSpam AND (?2 OR rid = "")
`.trim()))
  }

  get recentCommentsByUrlQuery () {
    return this._recentCommentsByUrlQuery ?? (this._recentCommentsByUrlQuery = this.DB.prepare(`
SELECT * FROM comment
WHERE
  (?1 OR url = ?2) AND
  NOT isSpam AND
  (?3 OR rid = "") AND
LIMIT ?4
`.trim()))
  }

  get readConfigQuery () {
    return this._readConfigQuery ?? (this._readConfigQuery =
      this.DB.prepare('SELECT value FROM config LIMIT 1')
    )
  }

  get writeConfigStmt () {
    return this._writeConfigStmt ?? (this._writeConfigStmt =
      this.DB.prepare('UPDATE config SET value = ?1')
    )
  }
}

let db

function setDb (DB) {
  if (db) {
    logger.log('重用已有数据库绑定')
    return
  }
  logger.log('创建新的数据库绑定')
  db = new DBBinding(DB)
}

export default {
  /**
   * @param {Request} request
   * @returns {Response}
   */
  async fetch (request, env) {
    setDb(env.DB)
    let event
    try {
      event = await request.json()
    } catch {
      event = {}
    }
    logger.log('请求 IP：', getIp(request))
    logger.log('请求函数：', event.event)
    logger.log('请求参数：', event)
    let res = {}
    const headers = {}
    try {
      protect(request)
      accessToken = anonymousSignIn(event)
      await readConfig()
      allowCors(request, headers)
      if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers })
      }
      switch (event.event) {
        case 'GET_FUNC_VERSION':
          res = getFuncVersion({ VERSION })
          break
        case 'COMMENT_GET':
          res = await commentGet(event)
          break
        case 'COMMENT_GET_FOR_ADMIN':
          res = await commentGetForAdmin(event)
          break
        case 'COMMENT_SET_FOR_ADMIN':
          res = await commentSetForAdmin(event)
          break
        case 'COMMENT_DELETE_FOR_ADMIN':
          res = await commentDeleteForAdmin(event)
          break
        case 'COMMENT_IMPORT_FOR_ADMIN':
          res = await commentImportForAdmin(event)
          break
        case 'COMMENT_LIKE':
          res = await commentLike(event)
          break
        case 'COMMENT_SUBMIT':
          res = await commentSubmit(event, request)
          break
        case 'COUNTER_GET':
          res = await counterGet(event)
          break
        case 'GET_PASSWORD_STATUS':
          res = await getPasswordStatus(config, VERSION)
          break
        case 'SET_PASSWORD':
          res = await setPassword(event)
          break
        case 'GET_CONFIG':
          res = await getConfig({ config, VERSION, isAdmin: isAdmin() })
          break
        case 'GET_CONFIG_FOR_ADMIN':
          res = await getConfigForAdmin({ config, isAdmin: isAdmin() })
          break
        case 'SET_CONFIG':
          res = await setConfig(event)
          break
        case 'LOGIN':
          res = await login(event.password)
          break
        case 'GET_COMMENTS_COUNT': // >= 0.2.7
          res = await getCommentsCount(event)
          break
        case 'GET_RECENT_COMMENTS': // >= 0.2.7
          res = await getRecentComments(event)
          break
        case 'EMAIL_TEST': // >= 1.4.6
          res = await emailTest(event, config, isAdmin())
        break
        case 'UPLOAD_IMAGE': // >= 1.5.0
          if (env.R2_PUBLIC_URL) {
            res = await r2_upload(event, env.R2, env.R2_PUBLIC_URL)
          } else {
            res = await uploadImage(event, config)
          }
          break
        case 'COMMENT_EXPORT_FOR_ADMIN': // >= 1.6.13
          res = await commentExportForAdmin(event)
          break
        default:
          if (event.event) {
            res.code = RES_CODE.EVENT_NOT_EXIST
            res.message = '请更新 Twikoo 云函数至最新版本'
          } else {
            res.code = RES_CODE.NO_PARAM
            res.message = 'Twikoo 云函数运行正常，请参考 https://twikoo.js.org/frontend.html 完成前端的配置'
            res.version = VERSION
          }
      }
    } catch (e) {
      logger.error('Twikoo 遇到错误，请参考以下错误信息。如有疑问，请反馈至 https://github.com/twikoojs/twikoo/issues')
      logger.error('请求参数：', event)
      logger.error('错误信息：', e)
      res.code = RES_CODE.FAIL
      res.message = e.message
    }
    if (!res.code && !request.body.accessToken) {
      res.accessToken = accessToken
    }
    logger.log('请求返回：', res)
    headers['content-type'] = 'application/json;charset=UTF-8'
    return new Response(JSON.stringify(res), { headers })
  }
}

function allowCors (request, headers) {
  const origin = request.headers.get('origin')
  if (origin) {
    headers['Access-Control-Allow-Credentials'] = true
    headers['Access-Control-Allow-Origin'] = getAllowedOrigin(origin)
    headers['Access-Control-Allow-Methods'] = 'POST'
    headers['Access-Control-Allow-Headers'] =
      'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
    headers['Access-Control-Max-Age'] = '600'
  }
}

function getAllowedOrigin (origin) {
  const localhostRegex = /^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0)(:\d{1,5})?$/
  if (localhostRegex.test(origin)) { // 判断是否为本地主机，如是则允许跨域
    return origin // Allow
  } else if (config.CORS_ALLOW_ORIGIN) { // 如设置了安全域名则检查
    // 适配多条 CORS 规则
    // 以逗号分隔 CORS
    const corsList = config.CORS_ALLOW_ORIGIN.split(',')
    // 遍历 CORS 列表
    for (let i = 0; i < corsList.length; i++) {
      const cors = corsList[i].replace(/\/$/, '') // 获取当前 CORS 并去除末尾的斜杠
      if (cors === origin) {
        return origin // Allow
      }
    }
    return '' // 不在安全域名列表中则禁止跨域
  } else {
    return origin // 未设置安全域名直接 Allow
  }
}

function anonymousSignIn (event) {
  if (event.accessToken) {
    return event.accessToken
  } else {
    return uuidv4().replace(/-/g, '')
  }
}

// 写入管理密码
async function setPassword (event) {
  const isAdminUser = isAdmin()
  // 如果数据库里没有密码，则写入密码
  // 如果数据库里有密码，则只有管理员可以写入密码
  if (config.ADMIN_PASS && !isAdminUser) {
    return { code: RES_CODE.PASS_EXIST, message: '请先登录再修改密码' }
  }
  const ADMIN_PASS = md5(event.password)
  await writeConfig({ ADMIN_PASS })
  return {
    code: RES_CODE.SUCCESS
  }
}

// 管理员登录
async function login (password) {
  if (!config) {
    return { code: RES_CODE.CONFIG_NOT_EXIST, message: '数据库无配置' }
  }
  if (!config.ADMIN_PASS) {
    return { code: RES_CODE.PASS_NOT_EXIST, message: '未配置管理密码' }
  }
  if (config.ADMIN_PASS !== md5(password)) {
    return { code: RES_CODE.PASS_NOT_MATCH, message: '密码错误' }
  }
  return {
    code: RES_CODE.SUCCESS
  }
}

// timestamp(2100/1/1) * 10
const MAX_TIMESTAMP_MILLIS = 41025312000000
const MAX_QUERY_LIMIT = 500

function parseLike (comment) {
  comment.like = JSON.parse(comment.like)
  return comment
}

// 读取评论
async function commentGet (event) {
  const res = {}
  try {
    validate(event, ['url'])
    const uid = getUid()
    const isAdminUser = isAdmin()
    const limit = parseInt(config.COMMENT_PAGE_SIZE) || 8
    let more = false
    const count = await db.commentCountQuery
      .bind(event.url, isAdminUser ? 2 : 1, uid)
      .first('count')
    // 读取主楼
    // 不包含置顶
    let { results: main } = await db.commentQuery
      .bind(
        event.url, isAdminUser ? 2 : 1, uid,
        event.before ?? MAX_TIMESTAMP_MILLIS, 0,
        // 流式分页，通过多读 1 条的方式，确认是否还有更多评论
        limit + 1
      ).all()

    if (main.length > limit) {
      // 还有更多评论
      more = true
      // 删除多读的 1 条
      main.splice(limit, 1)
    }
    let top = []
    if (!config.TOP_DISABLED && !event.before) {
      // 查询置顶评论
      top = (await db.commentQuery
        .bind(
          event.url, isAdminUser ? 2 : 1, uid, MAX_TIMESTAMP_MILLIS, 1,
          MAX_QUERY_LIMIT
        ).all()).results
      // 合并置顶评论和非置顶评论
      main = [
        ...top,
        ...main
      ]
    }
    // 读取回复楼
    const { results: reply } = await db.getReplyQuery(main.length)
      .bind(
        event.url, isAdminUser ? 2 : 1, uid, ...main.map((item) => item._id)
      ).all()
    res.data = parseComment([...main, ...reply].map(parseLike), uid, config)
    res.more = more
    res.count = count
  } catch (e) {
    res.data = []
    res.message = e.message
  }
  return res
}

// 管理员读取评论
async function commentGetForAdmin (event) {
  const res = {}
  const isAdminUser = isAdmin()
  if (isAdminUser) {
    validate(event, ['per', 'page'])
    const count = await db.commentForAdminCountQuery
      .bind(
        event.type === 'VISIBLE' ? 1 :
        event.type === 'HIDDEN' ? 0 :
        2,
        `%${event.keyword ?? ''}%`
      ).first('count')
    const { results: data } = await db.commentForAdminQuery.bind(
      event.type === 'VISIBLE' ? 1 :
      event.type === 'HIDDEN' ? 0 :
      2,
      `%${event.keyword ?? ''}%`,
      event.per,
      event.per * (event.page - 1)
    ).all()
    res.code = RES_CODE.SUCCESS
    res.count = count
    res.data = data
  } else {
    res.code = RES_CODE.NEED_LOGIN
    res.message = '请先登录'
  }
  return res
}

// 管理员修改评论
async function commentSetForAdmin (event) {
  const res = {}
  const isAdminUser = isAdmin()
  if (isAdminUser) {
    validate(event, ['id', 'set'])
    const fields = Object.keys(event.set).sort()
    await db.getCommentSetStmt(fields).bind(
      ...fields.map(field => event.set[field]), event.id,
    ).run()
    res.code = RES_CODE.SUCCESS
  } else {
    res.code = RES_CODE.NEED_LOGIN
    res.message = '请先登录'
  }
  return res
}

// 管理员删除评论
async function commentDeleteForAdmin (event) {
  const res = {}
  const isAdminUser = isAdmin()
  if (isAdminUser) {
    validate(event, ['id'])
    await db.commentDeleteStmt.bind(event.id).run()
    res.code = RES_CODE.SUCCESS
  } else {
    res.code = RES_CODE.NEED_LOGIN
    res.message = '请先登录'
  }
  return res
}

// 管理员导入评论
async function commentImportForAdmin (event) {
  const res = {}
  let logText = ''
  const log = (message) => {
    logText += `${new Date().toLocaleString()} ${message}\n`
  }
  const isAdminUser = isAdmin()
  if (isAdminUser) {
    try {
      validate(event, ['source', 'file'])
      log(`开始导入 ${event.source}`)
      let comments
      switch (event.source) {
        case 'valine': {
          const valineDb = await readFile(event.file, 'json', log)
          comments = await commentImportValine(valineDb, log)
          break
        }
        case 'disqus': {
          const disqusDb = await readFile(event.file, 'xml', log)
          comments = await commentImportDisqus(disqusDb, log)
          break
        }
        case 'artalk': {
          const artalkDb = await readFile(event.file, 'json', log)
          comments = await commentImportArtalk(artalkDb, log)
          break
        }
        case 'artalk2': {
          const artalkDb = await readFile(event.file, 'json', log)
          comments = await commentImportArtalk2(artalkDb, log)
          break
        }
        case 'twikoo': {
          const twikooDb = await readFile(event.file, 'json', log)
          comments = await commentImportTwikoo(twikooDb, log)
          break
        }
        default:
          throw new Error(`不支持 ${event.source} 的导入，请更新 Twikoo 云函数至最新版本`)
      }
      // TODO: 考虑并行导入
      for (const comment of comments) await save(comment)
      log(`导入成功`)
    } catch (e) {
      log(e.message)
    }
    res.code = RES_CODE.SUCCESS
    res.log = logText
    logger.info(logText)
  } else {
    res.code = RES_CODE.NEED_LOGIN
    res.message = '请先登录'
  }
  return res
}

async function commentExportForAdmin () {
  const res = {}
  const isAdminUser = isAdmin()
  if (isAdminUser) {
    const { results: data } = await db.commentExportQuery.all()
    res.code = RES_CODE.SUCCESS
    res.data = data
  } else {
    res.code = RES_CODE.NEED_LOGIN
    res.message = '请先登录'
  }
  return res
}

// 读取文件并转为 js object
async function readFile (file, type, log) {
  try {
    let content = file.toString('utf8')
    log('评论文件读取成功')
    if (type === 'json') {
      content = jsonParse(content)
      log('评论文件 JSON 解析成功')
    } else if (type === 'xml') {
      content = await xml2js.parseStringPromise(content)
      log('评论文件 XML 解析成功')
    }
    return content
  } catch (e) {
    log(`评论文件读取失败：${e.message}`)
  }
}

// 点赞 / 取消点赞
async function commentLike (event) {
  const res = {}
  validate(event, ['id'])
  await like(event.id, getUid())
  return res
}

// 点赞 / 取消点赞
async function like (id, uid) {
  const comment = await db.commentByIdQuery.bind(id).first()
  if (!comment) return
  let likes = JSON.parse(comment.like)
  if (likes.findIndex((item) => item === uid) === -1) {
    // 赞
    likes.push(uid)
  } else {
    // 取消赞
    likes = likes.filter((item) => item !== uid)
  }
  await db.updateLikeStmt.bind(id, JSON.stringify(likes)).run()
}

/**
 * 提交评论。分为多个步骤
 * 1. 参数校验
 * 2. 预检测垃圾评论（包括限流、人工审核、违禁词检测等）
 * 3. 保存到数据库
 * 4. 触发异步任务（包括 IM 通知、邮件通知、第三方垃圾评论检测
 *    等，因为这些任务比较耗时，所以要放在另一个线程进行）
 * @param {String} event.nick 昵称
 * @param {String} event.mail 邮箱
 * @param {String} event.link 网址
 * @param {String} event.ua UserAgent
 * @param {String} event.url 评论页地址
 * @param {String} event.comment 评论内容
 * @param {String} event.pid 回复的 ID
 * @param {String} event.rid 评论楼 ID
 */
async function commentSubmit (event, request) {
  const res = {}
  // 参数校验
  validate(event, ['url', 'ua', 'comment'])
  // 限流
  await limitFilter(request)
  // 验证码
  await checkCaptcha(event, request)
  // 预检测、转换
  const data = await parse(event, request)
  // 保存
  const comment = await save(data)
  res.id = comment.id
  // 异步垃圾检测、发送评论通知
  try {
    logger.log('开始异步垃圾检测、发送评论通知')
    logger.log('POST_SUBMIT')

    await Promise.race([
      (async () => {
        try {
          await postSubmit(comment)
        } catch (e) {
          logger.error('POST_SUBMIT 遇到错误')
          logger.error('请求参数：', comment)
          logger.error('错误信息：', e)
        }
      })(),
      // 如果超过 5 秒还没收到异步返回，直接继续，减少用户等待的时间
      new Promise((resolve) => setTimeout(resolve, 5000))
    ])
    logger.log('POST_SUBMIT')
  } catch (e) {
    logger.error('POST_SUBMIT 失败', e.message)
  }
  return res
}

// 保存评论
async function save (data) {
  data.id = data._id = uuidv4().replace(/-/g, '')
  await db.saveCommentStmt.bind(
    data._id, data.uid ?? '', data.nick ?? '', data.mail ?? '', data.mailMd5 ?? '',
    data.link ?? '', data.ua ?? '', data.ip ?? '', data.master ?? 0,
    data.url, data.href, data.comment, data.pid ?? '', data.rid ?? '',
    data.isSpam ?? 0, data.created, data.updated,
    JSON.stringify(data.like ?? []), data.top ?? 0, data.avatar ?? ''
  ).run()
  return data
}

async function getParentComment (currentComment) {
	return db.commentByIdQuery.bind(currentComment.pid).first()
}

// 异步垃圾检测、发送评论通知
async function postSubmit (comment) {
  // 垃圾检测
  const isSpam = await postCheckSpam(comment, config) ?? false
  await saveSpamCheckResult(comment, isSpam)
  // 发送通知
  await sendNotice(comment, config, getParentComment)
  return { code: RES_CODE.SUCCESS }
}

// 将评论转为数据库存储格式
async function parse (comment, request) {
  const timestamp = Date.now()
  const isAdminUser = isAdmin()
  const isBloggerMail = equalsMail(comment.mail, config.BLOGGER_EMAIL)
  if (isBloggerMail && !isAdminUser) throw new Error('请先登录管理面板，再使用博主身份发送评论')
  const hashMethod = config.GRAVATAR_CDN === 'cravatar.cn' ? md5 : sha256
  const commentDo = {
    _id: uuidv4().replace(/-/g, ''),
    uid: getUid(),
    nick: comment.nick ? comment.nick : '匿名',
    mail: comment.mail ? comment.mail : '',
    mailMd5: comment.mail ? hashMethod(normalizeMail(comment.mail)) : '',
    link: comment.link ? comment.link : '',
    ua: comment.ua,
    ip: getIp(request),
    master: isBloggerMail,
    url: comment.url,
    href: comment.href,
    comment: xss(comment.comment),
    pid: comment.pid ? comment.pid : comment.rid,
    rid: comment.rid,
    isSpam: isAdminUser ? false : preCheckSpam(comment, config),
    created: timestamp,
    updated: timestamp
  }
  if (isQQ(comment.mail)) {
    commentDo.mail = addQQMailSuffix(comment.mail)
    commentDo.mailMd5 = md5(normalizeMail(commentDo.mail))
    commentDo.avatar = await getQQAvatar(comment.mail)
  }
  return commentDo
}

// 限流
async function limitFilter (request) {
  // 限制每个 IP 每 10 分钟发表的评论数量
  let limitPerMinute = parseInt(config.LIMIT_PER_MINUTE)
  if (Number.isNaN(limitPerMinute)) limitPerMinute = 10
  // 限制所有 IP 每 10 分钟发表的评论数量
  let limitPerMinuteAll = parseInt(config.LIMIT_PER_MINUTE_ALL)
  if (Number.isNaN(limitPerMinuteAll)) limitPerMinuteAll = 10

  const getCountByIp = async () => limitPerMinute ?
    db.commentCountSinceByIpQuery.bind(
      Date.now() - 600000, getIp(request)
    ).first('count') : 0
  const getCount = async () => limitPerMinuteAll ?
    db.commentCountSinceQuery.bind(Date.now() - 600000).first('count') : 0
  const [countByIp, count] = await Promise.all([getCountByIp(), getCount()])

  if (countByIp > limitPerMinute) throw new Error('发言频率过高')
  if (count > limitPerMinuteAll) throw new Error('评论太火爆啦 >_< 请稍后再试')
}

async function checkCaptcha (comment, request) {
  if (config.TURNSTILE_SITE_KEY && config.TURNSTILE_SECRET_KEY) {
    await checkTurnstileCaptcha({
      ip: getIp(request),
      turnstileToken: comment.turnstileToken,
      turnstileTokenSecretKey: config.TURNSTILE_SECRET_KEY
    })
  }
}

async function checkTurnstileCaptcha ({ ip, turnstileToken, turnstileTokenSecretKey }) {
  try {
    const formData = new FormData()
    formData.append('secret', turnstileTokenSecretKey)
    formData.append('response', turnstileToken)
    formData.append('remoteip', ip)
    const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: formData,
    })
    const data = await resp.json()
    logger.log('验证码检测结果', data)
    if (!data.success) throw new Error('验证码错误')
  } catch (e) {
    throw new Error('验证码检测失败: ' + e.message)
  }
}

async function saveSpamCheckResult (comment, isSpam) {
  comment.isSpam = isSpam
  await db.updateIsSpamStmt.bind(comment._id, isSpam, Date.now()).run()
}

/**
 * 获取文章点击量
 * @param {String} event.url 文章地址
 */
async function counterGet (event) {
  const res = {}
  try {
    validate(event, ['url'])
    await db.incCounterStmt.bind(event.url, event.title, Date.now()).run()
    res.time = await db.counterQuery.bind(event.url).first('time')
  } catch (e) {
    res.message = e.message
    return res
  }
  return res
}

/**
 * 批量获取文章评论数 API
 * @param {Array} event.urls 不包含协议和域名的文章路径列表，必传参数
 * @param {Boolean} event.includeReply 评论数是否包括回复，默认：false
 */
async function getCommentsCount (event) {
  const res = {}
  try {
    validate(event, ['urls'])
    res.data = await Promise.all(event.urls.map(
      async (url) => ({
        url,
        count: await db.commentCountByUrlQuery
          .bind(url, event.includeReply)
          .first('count'),
      })))
  } catch (e) {
    res.message = e.message
    return res
  }
  return res
}

/**
 * 获取最新评论 API
 * @param {Boolean} event.includeReply 评论数是否包括回复，默认：false
 */
async function getRecentComments (event) {
  const res = {}
  try {
    if (event.pageSize > 100) event.pageSize = 100
    let result
    if (event.urls && event.urls.length) {
      result = await db.recentCommentsByUrlQuery.bind(
        1, '', event.includeReply, event.pageSize || 10
      ).all()
    } else {
      result = (await Promise.all(event.urls.map(
        (url) => db.recentCommentsByUrlQuery.bind(
          0, url, event.includeReply, event.pageSize || 10
        ).all()
      ))).flat()
    }
    res.data = result.map((comment) => {
      return {
        id: comment._id.toString(),
        url: comment.url,
        nick: comment.nick,
        avatar: getAvatar(comment, config),
        mailMd5: getMailMd5(comment),
        link: comment.link,
        comment: comment.comment,
        commentText: $(comment.comment).text(),
        created: comment.created
      }
    })
  } catch (e) {
    res.message = e.message
    return res
  }
  return res
}

// 修改配置
async function setConfig (event) {
  const isAdminUser = isAdmin()
  if (isAdminUser) {
    await writeConfig(event.config)
    return {
      code: RES_CODE.SUCCESS
    }
  } else {
    return {
      code: RES_CODE.NEED_LOGIN,
      message: '请先登录'
    }
  }
}

function protect (request) {
  // 防御
  const ip = getIp(request)
  requestTimes[ip] = (requestTimes[ip] || 0) + 1
  if (requestTimes[ip] > MAX_REQUEST_TIMES) {
    logger.warn(`${ip} 当前请求次数为 ${requestTimes[ip]}，已超过最大请求次数`)
    throw new Error('Too Many Requests')
  } else {
    logger.log(`${ip} 当前请求次数为 ${requestTimes[ip]}`)
  }
}

// 读取配置
async function readConfig () {
  const configStr = await db.readConfigQuery.first('value')
  return config = configStr ? JSON.parse(configStr) : {}
}

// 写入配置
async function writeConfig (newConfig) {
  if (!Object.keys(newConfig).length) return
  logger.info('写入配置：', newConfig)
  try {
    const config = { ...await readConfig(), ...newConfig }
    await db.writeConfigStmt.bind(JSON.stringify(config)).run()
  } catch (e) {
    logger.error('写入配置失败：', e)
  }
}

// 获取用户 ID
function getUid () {
  return accessToken
}

// 判断用户是否管理员
function isAdmin () {
  const uid = getUid()
  return config.ADMIN_PASS === md5(uid)
}

function getIp (request) {
  return request.headers.get('CF-Connecting-IP')
}

// R2上传图片
async function r2_upload(event, cdnUrl) {
  const { photo } = event
  const res = {}
  try {
    if (cdnUrl.endsWith('/')) {
      cdnUrl = cdnUrl.substring(0, cdnUrl.length - 1)
    }
    const now = new Date()
    const year = now.getFullYear()
    const month = now.getMonth() + 1
    const path = month < 10 ? `${year}/0${month}/` : `${year}/${month}/`
    let filename = md5(photo)
    const blob = dataURIToBlob(photo)
    const mime = blob.type.split('/')
    if (mime.length > 1) {
      filename += '.' + mime[1].trim()
    }
    // 🚨 这里删掉 bucket.put，直接返回 publicURL 拼接的地址
    res.code = 0
    res.data = {
      name: filename,
      size: blob.size,
      url: `${cdnUrl}/${path}${filename}`
    }
  } catch (e) {
    logger.error(e)
    res.code = 1040
    res.err = e.message
  }
  return res
}

function dataURIToBlob(dataURI) {
  // 分离 MIME 类型和 base64 数据
  const [header, base64] = dataURI.split(',');
  const mime = header.match(/:(.*?);/)[1];

  // 解码 base64 数据
  const binaryString = atob(base64);
  const len = binaryString.length;

  // 创建 Uint8Array 存储二进制数据
  const uint8Array = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
      uint8Array[i] = binaryString.charCodeAt(i);
  }

  // 创建 Blob 对象
  return new Blob([uint8Array], { type: mime });
}
