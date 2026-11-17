// dsh-scan-triage 入口：把 skills/scan-triage 注册为按需加载的技能。
//
// 「安全研判」Agent 预设由 cordis.patch.yml 声明，不经过这里。
// 本文件只在 apply() 中读取随包的 SKILL.md，不联网、不写文件、不启动进程。
import { readFileSync } from 'node:fs'
import { dirname, join, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

export const name = 'dsh-scan-triage'
export const inject = ['skills']

const SKILL_NAME = 'scan-triage'
const packageRoot = dirname(fileURLToPath(import.meta.url))
const FALLBACK_DESCRIPTION =
  '研判网络安全扫描结果、告警与日志：识别工具与扫描方式，按真实风险分级，甄别误报，给出处置与复测方法。仅用于防御。'

/**
 * 拆分 SKILL.md 的 YAML 头和正文，只取单行的 description。
 * 头部缺失或格式不对时，整份文本作为正文。
 * @param {string} text SKILL.md 原文
 * @returns {{ description: string | undefined, body: string }}
 */
export function splitFrontmatter(text) {
  const source = text.replace(/^﻿/, '')
  const open = /^---\r?\n/.exec(source)
  if (!open) return { description: undefined, body: source }
  const rest = source.slice(open[0].length)
  const close = /\r?\n---[ \t]*(?:\r?\n|$)/.exec(rest)
  if (!close) return { description: undefined, body: source }
  const meta = rest.slice(0, close.index)
  const body = rest.slice(close.index + close[0].length).replace(/^(?:[ \t]*\r?\n)+/, '')
  const match = /^description:[ \t]*(.+?)[ \t]*$/m.exec(meta)
  const raw = match?.[1]?.trim()
  const description = raw?.replace(/^(['"])(.*)\1$/, '$2')
  return { description: description || undefined, body }
}

/**
 * 注册技能。注册是一个 effect：插件卸载时自动撤销。
 * @param {any} ctx 注入了 skills 服务的 Cordis 上下文
 */
export function apply(ctx) {
  const skillDir = join(packageRoot, 'skills', SKILL_NAME)
  const { description, body } = splitFrontmatter(readFileSync(join(skillDir, 'SKILL.md'), 'utf8'))
  ctx.effect(
    () =>
      ctx.skills.register({
        name: SKILL_NAME,
        source: 'bundled',
        description: description ?? FALLBACK_DESCRIPTION,
        content: body,
        resourceBase: { kind: 'directory', path: skillDir.split(sep).join('/') },
      }),
    'dsh-scan-triage.skill',
  )
}
