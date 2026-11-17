#!/usr/bin/env node
// nmap-summary.mjs：把 Nmap XML（-oX / -oA 生成的 .xml）整理成简明的研判摘要。
// 只读取指定的文件；不联网、不执行扫描、不修改原文件。零依赖，Node 18 及以上可运行。
//
// 用法：node nmap-summary.mjs <scan.xml> [--out 报告.md] [--json] [--max-hosts N]

import { readFileSync, realpathSync, writeFileSync } from 'node:fs'
import { basename } from 'node:path'
import { fileURLToPath } from 'node:url'

const HELP = `用法：node nmap-summary.mjs <scan.xml> [选项]

选项：
  --out <文件>     把完整报告（全部主机明细）写入 Markdown 文件，终端只输出概览
  --json           以 JSON 输出完整解析结果，便于再加工
  --max-hosts <N>  终端最多展示多少台主机的明细（默认 10）
  -h, --help       显示本说明

脚本只读取指定文件，不联网、不扫描、不修改原文件。`

const SCRIPT_OUTPUT_LIMIT = 240
const ROWS_PER_HOST_LIMIT = 40

// ---------- 端口与服务提示 ----------

const OT_NOTE = '工控协议，通常无认证；不应能从办公网访问；复测须控制速率、避开生产时段'

const PORT_NOTES = new Map([
  ['21/tcp', 'FTP 明文；查匿名登录与弱口令'],
  ['22/tcp', 'SSH；限制来源网段，查弱口令，版本类漏洞注意补丁回移'],
  ['23/tcp', 'Telnet 明文；建议关闭改用 SSH'],
  ['25/tcp', 'SMTP；查开放中继'],
  ['53/tcp', 'DNS；查对外递归与区域传送'],
  ['53/udp', 'DNS；查对外递归'],
  ['69/udp', 'TFTP 无认证'],
  ['111/tcp', 'rpcbind；暴露 RPC/NFS 信息'],
  ['111/udp', 'rpcbind；暴露 RPC/NFS 信息'],
  ['135/tcp', 'MS-RPC；不应跨安全区域开放'],
  ['137/udp', 'NetBIOS；信息泄露'],
  ['139/tcp', 'NetBIOS；不应跨安全区域开放'],
  ['161/udp', 'SNMP；查默认团体名，建议 SNMPv3 并限制来源'],
  ['389/tcp', 'LDAP；查匿名绑定'],
  ['445/tcp', 'SMB；查 SMBv1 与 MS17-010 类漏洞，不应跨区域开放'],
  ['512/tcp', 'rexec 明文；建议关闭'],
  ['513/tcp', 'rlogin 明文；建议关闭'],
  ['514/tcp', 'rsh 明文；建议关闭'],
  ['873/tcp', 'rsync；查未授权访问'],
  ['1080/tcp', 'SOCKS 代理；查是否为开放代理'],
  ['1433/tcp', 'SQL Server；只应对应用服务器开放'],
  ['1521/tcp', 'Oracle；只应对应用服务器开放'],
  ['2049/tcp', 'NFS；查共享权限'],
  ['2181/tcp', 'ZooKeeper；查未授权访问'],
  ['2375/tcp', 'Docker API 未加密；未授权即可控制宿主机'],
  ['2379/tcp', 'etcd；查认证与 TLS'],
  ['3306/tcp', 'MySQL；只应对应用服务器开放，禁止 root 远程登录'],
  ['3389/tcp', 'RDP；不应对互联网开放，开启 NLA，经 VPN/堡垒机'],
  ['4444/tcp', '常被后门或渗透工具使用；到主机上查监听进程'],
  ['5432/tcp', 'PostgreSQL；只应对应用服务器开放'],
  ['5800/tcp', 'VNC；查弱口令或无口令'],
  ['5900/tcp', 'VNC；查弱口令或无口令'],
  ['5985/tcp', 'WinRM；只应对管理网段开放'],
  ['5986/tcp', 'WinRM；只应对管理网段开放'],
  ['6379/tcp', 'Redis；查未授权访问，绑定内网并设置密码'],
  ['6443/tcp', 'Kubernetes API；禁止匿名访问'],
  ['7001/tcp', 'WebLogic；历史高危漏洞多，核对版本与补丁'],
  ['8009/tcp', 'Tomcat AJP；Ghostcat（CVE-2020-1938），不用就关闭'],
  ['9200/tcp', 'Elasticsearch；查未授权访问'],
  ['10250/tcp', 'kubelet；查匿名认证'],
  ['11211/tcp', 'Memcached；查未授权访问'],
  ['11211/udp', 'Memcached UDP；可被用于反射放大，建议关闭'],
  ['27017/tcp', 'MongoDB；查未授权访问'],
  ['102/tcp', `S7comm（西门子 PLC）；${OT_NOTE}`],
  ['502/tcp', `Modbus/TCP；${OT_NOTE}`],
  ['2404/tcp', `IEC 60870-5-104；${OT_NOTE}`],
  ['4840/tcp', `OPC UA；${OT_NOTE}`],
  ['20000/tcp', `DNP3；${OT_NOTE}`],
  ['44818/tcp', `EtherNet/IP；${OT_NOTE}`],
  ['47808/udp', `BACnet；${OT_NOTE}`],
])

// 服务跑在非标准端口时，按服务名提示
const SERVICE_NOTES = new Map([
  ['ftp', 'FTP 明文；查匿名登录与弱口令'],
  ['telnet', 'Telnet 明文；建议关闭改用 SSH'],
  ['microsoft-ds', 'SMB；查 SMBv1 与 MS17-010 类漏洞'],
  ['ms-wbt-server', 'RDP；不应对互联网开放，开启 NLA'],
  ['vnc', 'VNC；查弱口令或无口令'],
  ['redis', 'Redis；查未授权访问'],
  ['mongodb', 'MongoDB；查未授权访问'],
  ['mysql', 'MySQL；只应对应用服务器开放'],
  ['ms-sql-s', 'SQL Server；只应对应用服务器开放'],
  ['postgresql', 'PostgreSQL；只应对应用服务器开放'],
  ['rsync', 'rsync；查未授权访问'],
  ['memcache', 'Memcached；查未授权访问'],
  ['docker', 'Docker API；查是否未加密、未授权'],
  ['ajp13', 'Tomcat AJP；Ghostcat（CVE-2020-1938）'],
])

// ---------- 参数 ----------

function parseArgs(argv) {
  const opts = { file: null, out: null, json: false, maxHosts: 10, help: false }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '-h' || a === '--help') opts.help = true
    else if (a === '--json') opts.json = true
    else if (a === '--out') opts.out = argv[++i] ?? null
    else if (a === '--max-hosts') opts.maxHosts = Number(argv[++i])
    else if (a.startsWith('--')) throw new UsageError(`未知选项：${a}`)
    else if (opts.file === null) opts.file = a
    else throw new UsageError(`多余的参数：${a}`)
  }
  if (!opts.help && !opts.file) throw new UsageError('缺少 XML 文件路径')
  if (opts.out === '') throw new UsageError('--out 需要一个文件路径')
  if (!Number.isInteger(opts.maxHosts) || opts.maxHosts < 0) throw new UsageError('--max-hosts 需要一个非负整数')
  return opts
}

class UsageError extends Error {}

// ---------- 读取与解码 ----------

function readText(path) {
  const buf = readFileSync(path)
  // PowerShell 5 用 > 重定向时会写成 UTF-16LE，这里一并处理
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) return buf.subarray(2).toString('utf16le')
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
    const swapped = Buffer.from(buf.subarray(2))
    swapped.swap16()
    return swapped.toString('utf16le')
  }
  const text = buf.toString('utf8')
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text
}

const NAMED_ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }

function decodeEntities(s) {
  if (!s.includes('&')) return s
  return s.replace(/&(#[xX][0-9a-fA-F]+|#\d+|amp|lt|gt|quot|apos);/g, (m, e) => {
    if (e[0] !== '#') return NAMED_ENTITIES[e]
    const cp = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10)
    return Number.isInteger(cp) && cp >= 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : m
  })
}

// ---------- 极简 XML 标签扫描（只解析 Nmap 输出用到的标签和属性） ----------

function* scanTags(xml) {
  const n = xml.length
  let i = 0
  while (i < n) {
    const lt = xml.indexOf('<', i)
    if (lt === -1) return
    if (xml.startsWith('<!--', lt)) {
      const end = xml.indexOf('-->', lt + 4)
      if (end === -1) return
      i = end + 3
      continue
    }
    if (xml.startsWith('<![CDATA[', lt)) {
      const end = xml.indexOf(']]>', lt + 9)
      if (end === -1) return
      i = end + 3
      continue
    }
    if (xml.startsWith('<?', lt)) {
      const end = xml.indexOf('?>', lt + 2)
      if (end === -1) return
      i = end + 2
      continue
    }
    if (xml.startsWith('<!', lt)) {
      let j = lt + 2
      let depth = 0
      for (; j < n; j++) {
        const c = xml[j]
        if (c === '[') depth++
        else if (c === ']') depth--
        else if (c === '>' && depth <= 0) break
      }
      i = j + 1
      continue
    }
    let j = lt + 1
    let quote = null
    for (; j < n; j++) {
      const c = xml[j]
      if (quote !== null) {
        if (c === quote) quote = null
      } else if (c === '"' || c === "'") quote = c
      else if (c === '>') break
    }
    if (j >= n) return // 文件在标签中途结束
    const raw = xml.slice(lt + 1, j)
    i = j + 1
    if (raw[0] === '/') {
      yield { type: 'close', name: raw.slice(1).trim() }
      continue
    }
    const selfClosing = raw.endsWith('/')
    const body = selfClosing ? raw.slice(0, -1) : raw
    const nameMatch = /^[^\s/>]+/.exec(body)
    if (!nameMatch) continue
    const name = nameMatch[0]
    const attrs = {}
    const re = /([^\s=]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g
    const rest = body.slice(name.length)
    let a
    while ((a = re.exec(rest)) !== null) attrs[a[1]] = decodeEntities(a[2] ?? a[3] ?? '')
    yield { type: 'open', name, attrs, selfClosing }
  }
}

// ---------- 解析 ----------

function num(v) {
  if (v === undefined || v === '') return null
  const x = Number(v)
  return Number.isFinite(x) ? x : null
}

export function parseNmapXml(xml) {
  const scan = {
    version: '', args: '', startstr: '', start: null,
    scaninfo: [], finished: null, hostsStat: null, prescripts: [], postscripts: [],
  }
  const hosts = []
  const stack = []
  let sawRoot = false
  let host = null
  let port = null

  const closeHost = () => {
    if (port) { host.ports.push(port); port = null }
    hosts.push(host)
    host = null
  }

  for (const t of scanTags(xml)) {
    if (t.type === 'close') {
      const idx = stack.lastIndexOf(t.name)
      if (idx !== -1) stack.length = idx
      if (t.name === 'port' && host && port) { host.ports.push(port); port = null }
      else if (t.name === 'host' && host) closeHost()
      continue
    }
    const { name, attrs, selfClosing } = t
    const parent = stack[stack.length - 1]
    switch (name) {
      case 'nmaprun':
        sawRoot = true
        scan.version = attrs.version ?? ''
        scan.args = attrs.args ?? ''
        scan.startstr = attrs.startstr ?? ''
        scan.start = num(attrs.start)
        break
      case 'scaninfo':
        scan.scaninfo.push({ type: attrs.type ?? '', protocol: attrs.protocol ?? '', numservices: num(attrs.numservices) ?? 0 })
        break
      case 'host':
        if (host) closeHost()
        host = { status: 'unknown', reason: '', addresses: [], hostnames: [], ports: [], extraports: [], scripts: [], os: [] }
        break
      case 'status':
        if (host && parent === 'host') { host.status = attrs.state ?? 'unknown'; host.reason = attrs.reason ?? '' }
        break
      case 'address':
        if (host && parent === 'host') host.addresses.push({ addr: attrs.addr ?? '', type: attrs.addrtype ?? '', vendor: attrs.vendor ?? '' })
        break
      case 'hostname':
        if (host && parent === 'hostnames' && attrs.name) host.hostnames.push(attrs.name)
        break
      case 'extraports':
        if (host && parent === 'ports') host.extraports.push({ state: attrs.state ?? '', count: num(attrs.count) ?? 0 })
        break
      case 'port':
        if (host && parent === 'ports') {
          port = { protocol: attrs.protocol ?? '', portid: num(attrs.portid) ?? 0, state: '', reason: '', service: null, scripts: [] }
          if (selfClosing) { host.ports.push(port); port = null }
        }
        break
      case 'state':
        if (port && parent === 'port') { port.state = attrs.state ?? ''; port.reason = attrs.reason ?? '' }
        break
      case 'service':
        if (port && parent === 'port') {
          port.service = {
            name: attrs.name ?? '', product: attrs.product ?? '', version: attrs.version ?? '',
            extrainfo: attrs.extrainfo ?? '', ostype: attrs.ostype ?? '', tunnel: attrs.tunnel ?? '',
            method: attrs.method ?? '', conf: num(attrs.conf),
          }
        }
        break
      case 'script': {
        const s = { id: attrs.id ?? '', output: attrs.output ?? '' }
        if (port && parent === 'port') port.scripts.push(s)
        else if (host && parent === 'hostscript') host.scripts.push(s)
        else if (parent === 'prescript') scan.prescripts.push(s)
        else if (parent === 'postscript') scan.postscripts.push(s)
        break
      }
      case 'osmatch':
        if (host && parent === 'os') host.os.push({ name: attrs.name ?? '', accuracy: num(attrs.accuracy) ?? 0 })
        break
      case 'finished':
        if (parent === 'runstats') {
          scan.finished = { timestr: attrs.timestr ?? '', elapsed: num(attrs.elapsed), exit: attrs.exit ?? '', summary: attrs.summary ?? '', errormsg: attrs.errormsg ?? '' }
        }
        break
      case 'hosts':
        if (parent === 'runstats') scan.hostsStat = { up: num(attrs.up) ?? 0, down: num(attrs.down) ?? 0, total: num(attrs.total) ?? 0 }
        break
      default:
        break
    }
    if (!selfClosing) stack.push(name)
  }
  if (host) closeHost()
  return { sawRoot, complete: scan.finished !== null, scan, hosts }
}

// ---------- 分析 ----------

function ipKey(ip) {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip)
  if (!m) return [1, ip]
  return [0, m.slice(1).reduce((acc, x) => acc * 256 + Number(x), 0)]
}

function compareIp(a, b) {
  const ka = ipKey(a)
  const kb = ipKey(b)
  if (ka[0] !== kb[0]) return ka[0] - kb[0]
  return ka[1] < kb[1] ? -1 : ka[1] > kb[1] ? 1 : 0
}

function serviceLabel(p) {
  const s = p.service
  if (!s || !s.name) return '-'
  return s.tunnel ? `${s.tunnel}/${s.name}` : s.name
}

function productLabel(p) {
  const s = p.service
  if (!s) return ''
  const parts = [s.product, s.version].filter(Boolean).join(' ')
  return [parts, s.extrainfo ? `(${s.extrainfo})` : ''].filter(Boolean).join(' ')
}

function portFlags(p) {
  const flags = []
  const key = `${p.portid}/${p.protocol}`
  const s = p.service
  let attention = false
  if (PORT_NOTES.has(key)) { flags.push(PORT_NOTES.get(key)); attention = true }
  else if (s && SERVICE_NOTES.has(s.name)) { flags.push(`${SERVICE_NOTES.get(s.name)}（非标准端口）`); attention = true }
  if (s && s.name === 'tcpwrapped') flags.push('tcpwrapped：握手后被断开，服务未知，常见于访问控制或防护设备')
  else if (s && s.method === 'table') flags.push('服务名只按端口号推测，未经探测确认')
  if (p.state === 'open|filtered') flags.push('无法区分开放与过滤（UDP 常见）')
  return { flags, attention }
}

export function analyze(parsed) {
  const { scan } = parsed
  const hosts = parsed.hosts.map((h) => {
    const v4 = h.addresses.find((a) => a.type === 'ipv4')
    const v6 = h.addresses.find((a) => a.type === 'ipv6')
    const mac = h.addresses.find((a) => a.type === 'mac')
    const ip = (v4 ?? v6 ?? h.addresses[0])?.addr ?? '(无地址)'
    const ports = h.ports
      .map((p) => ({ ...p, ...portFlags(p) }))
      .sort((a, b) => a.protocol.localeCompare(b.protocol) || a.portid - b.portid)
    const open = ports.filter((p) => p.state === 'open')
    const uncertain = ports.filter((p) => p.state === 'open|filtered')
    const notes = []
    if (open.length > 100) notes.push(`开放端口多达 ${open.length} 个，可能是防护设备、SYN 代理或蜜罐代答，需核实`)
    return {
      ip,
      hostnames: h.hostnames,
      mac: mac ? { addr: mac.addr, vendor: mac.vendor } : null,
      status: h.status,
      reason: h.reason,
      os: h.os.slice().sort((a, b) => b.accuracy - a.accuracy)[0] ?? null,
      extraports: h.extraports,
      ports,
      open,
      uncertain,
      attentionCount: open.filter((p) => p.attention).length,
      scripts: h.scripts,
      notes,
    }
  })
  hosts.sort((a, b) => compareIp(a.ip, b.ip))

  const up = hosts.filter((h) => h.status === 'up')
  const withOpen = up.filter((h) => h.open.length > 0)

  const byPort = new Map()
  for (const h of up) {
    for (const p of h.open) {
      const key = `${p.portid}/${p.protocol}`
      if (!byPort.has(key)) byPort.set(key, { key, portid: p.portid, protocol: p.protocol, services: new Set(), hosts: [], note: '' })
      const entry = byPort.get(key)
      entry.services.add(serviceLabel(p))
      entry.hosts.push(h.ip)
      if (p.attention && !entry.note) entry.note = p.flags[0]
    }
  }
  const portStats = [...byPort.values()]
    .map((e) => ({ ...e, services: [...e.services] }))
    .sort((a, b) => b.hosts.length - a.hosts.length || a.portid - b.portid)

  const hints = []
  const allOpen = up.flatMap((h) => h.open)
  const probed = allOpen.some((p) => p.service && p.service.method === 'probed')
  if (allOpen.length > 0 && !probed) hints.push('未做版本探测（没有加 -sV）：服务名只是按端口号推测，版本类问题无法判断。')
  if (!scan.scaninfo.some((s) => s.protocol === 'udp')) hints.push('未扫描 UDP：SNMP、DNS、NTP 等 UDP 服务不在结果里。')
  const tcpInfo = scan.scaninfo.find((s) => s.protocol === 'tcp')
  if (tcpInfo && tcpInfo.numservices > 0 && tcpInfo.numservices < 65535) {
    hints.push(`TCP 只扫描了 ${tcpInfo.numservices} 个端口（不是全端口），非常用端口上的服务可能被漏掉。`)
  }
  const udpInfo = scan.scaninfo.find((s) => s.protocol === 'udp')
  if (udpInfo && udpInfo.numservices > 0 && udpInfo.numservices < 65535) {
    hints.push(`UDP 只扫描了 ${udpInfo.numservices} 个端口，其余 UDP 服务不在结果里。`)
  }
  if (/(^|\s)-Pn(\s|$)/.test(scan.args)) hints.push('使用了 -Pn（跳过主机发现）：“存活”主机数不代表真实在线情况。')
  if (probed) hints.push('版本号来自服务 Banner：Linux 发行版常向后移植补丁，按版本号判定的漏洞需到主机上核对（见 references/false-positives.md）。')
  if (!parsed.complete) hints.push('文件不完整（缺少结束统计），扫描可能被中断，结果只是部分主机。')
  if (scan.finished && scan.finished.exit && scan.finished.exit !== 'success') {
    hints.push(`Nmap 报告异常退出：${scan.finished.errormsg || scan.finished.exit}`)
  }

  return {
    scan,
    complete: parsed.complete,
    hosts,
    up,
    withOpen,
    upWithoutOpen: up.filter((h) => h.open.length === 0),
    portStats,
    attention: portStats.filter((e) => e.note),
    totalOpen: allOpen.length,
    hints,
  }
}

// ---------- 输出 ----------

function cell(s) {
  return String(s ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ').trim() || '-'
}

function oneLine(s, limit) {
  const flat = String(s ?? '').replace(/\s+/g, ' ').trim()
  return flat.length > limit ? `${flat.slice(0, limit)}…（已截断）` : flat
}

function listHosts(ips, limit) {
  return ips.length > limit ? `${ips.slice(0, limit).join(', ')} 等 ${ips.length} 台` : ips.join(', ')
}

const SCAN_TYPES = {
  syn: 'SYN 半开扫描', connect: 'TCP 连接扫描', udp: 'UDP 扫描', ack: 'ACK 扫描', window: 'Window 扫描',
  maimon: 'Maimon 扫描', fin: 'FIN 扫描', null: 'NULL 扫描', xmas: 'Xmas 扫描', ipproto: 'IP 协议扫描',
  sctpinit: 'SCTP INIT 扫描', sctpcookieecho: 'SCTP COOKIE-ECHO 扫描', idle: 'Idle 扫描', bounce: 'FTP Bounce 扫描',
}

function scanTypeLabel(x) {
  const label = SCAN_TYPES[x.type] ?? `${x.type} 扫描`
  return `${label}（${x.protocol.toUpperCase()}，${x.numservices} 个端口）`
}

function renderOverview(r, fileLabel) {
  const s = r.scan
  const lines = []
  lines.push(`# Nmap 扫描摘要：${fileLabel}`, '')
  lines.push('## 扫描信息', '')
  const meta = []
  if (s.version) meta.push(`Nmap ${s.version}`)
  if (s.startstr) meta.push(`开始于 ${s.startstr}`)
  if (s.finished && s.finished.elapsed !== null) meta.push(`耗时 ${Math.round(s.finished.elapsed)} 秒`)
  if (meta.length) lines.push(`- ${meta.join('；')}`)
  if (s.args) lines.push(`- 命令：\`${s.args.replace(/`/g, "'")}\``)
  if (s.scaninfo.length) {
    lines.push(`- 扫描方式：${s.scaninfo.map(scanTypeLabel).join('、')}`)
  }
  const total = s.hostsStat ? s.hostsStat.total : r.hosts.length
  lines.push(`- 主机：存活 ${r.up.length} 台${total ? ` / 共扫描 ${total} 个地址` : ''}；其中 ${r.withOpen.length} 台有开放端口，开放端口共 ${r.totalOpen} 个`)
  lines.push(`- 文件完整性：${r.complete ? '完整' : '不完整（扫描可能被中断）'}`)
  lines.push('')
  if (r.hints.length) {
    lines.push('## 识别提示（影响结论可信度）', '')
    for (const h of r.hints) lines.push(`- ${h}`)
    lines.push('')
  }
  if (r.attention.length) {
    lines.push('## 需关注的端口（按端口汇总）', '')
    lines.push('| 端口 | 服务 | 主机数 | 主机 | 提示 |', '|---|---|---|---|---|')
    for (const e of r.attention) {
      lines.push(`| ${e.key} | ${cell(e.services.join(', '))} | ${e.hosts.length} | ${cell(listHosts(e.hosts, 5))} | ${cell(e.note)} |`)
    }
    lines.push('')
  }
  if (r.portStats.length) {
    lines.push('## 开放端口分布（前 10）', '')
    lines.push('| 端口 | 服务 | 主机数 |', '|---|---|---|')
    for (const e of r.portStats.slice(0, 10)) lines.push(`| ${e.key} | ${cell(e.services.join(', '))} | ${e.hosts.length} |`)
    lines.push('')
  }
  return lines
}

function renderHost(h) {
  const lines = []
  const title = h.hostnames.length ? `${h.ip}（${h.hostnames.join(', ')}）` : h.ip
  lines.push(`### ${title}`, '')
  const facts = []
  if (h.mac) facts.push(`MAC ${h.mac.addr}${h.mac.vendor ? `（${h.mac.vendor}）` : ''}`)
  if (h.os) facts.push(`系统推测：${h.os.name}（${h.os.accuracy}%）`)
  const extra = h.extraports.filter((e) => e.count > 0).map((e) => `${e.state} ${e.count} 个`)
  if (extra.length) facts.push(`其余端口：${extra.join('，')}`)
  if (facts.length) lines.push(`- ${facts.join('｜')}`)
  for (const note of h.notes) lines.push(`- 注意：${note}`)
  const rows = [...h.open, ...h.uncertain]
  if (rows.length) {
    if (facts.length || h.notes.length) lines.push('')
    lines.push('| 端口 | 状态 | 服务 | 产品/版本 | 提示 |', '|---|---|---|---|---|')
    for (const p of rows.slice(0, ROWS_PER_HOST_LIMIT)) {
      lines.push(`| ${p.portid}/${p.protocol} | ${cell(p.state)} | ${cell(serviceLabel(p))} | ${cell(productLabel(p))} | ${cell(p.flags.join('；'))} |`)
    }
    if (rows.length > ROWS_PER_HOST_LIMIT) lines.push('', `- 另有 ${rows.length - ROWS_PER_HOST_LIMIT} 个端口未列出，用 --json 查看全部。`)
  }
  const scripts = [
    ...rows.flatMap((p) => p.scripts.map((sc) => ({ where: `${p.portid}/${p.protocol}`, ...sc }))),
    ...h.scripts.map((sc) => ({ where: '主机', ...sc })),
  ]
  if (scripts.length) {
    lines.push('', '脚本输出：')
    for (const sc of scripts) lines.push(`- [${sc.where}] ${sc.id}：${oneLine(sc.output, SCRIPT_OUTPUT_LIMIT)}`)
  }
  lines.push('')
  return lines
}

function prioritized(hosts) {
  return hosts.slice().sort((a, b) => b.attentionCount - a.attentionCount || b.open.length - a.open.length || compareIp(a.ip, b.ip))
}

export function renderMarkdown(r, fileLabel, { maxHosts, full }) {
  const lines = renderOverview(r, fileLabel)
  const ordered = full ? r.withOpen : prioritized(r.withOpen)
  const shown = full ? ordered : ordered.slice(0, maxHosts)
  if (shown.length) {
    lines.push(full ? `## 主机明细（共 ${ordered.length} 台）` : `## 主机明细（按关注程度展示 ${shown.length} / ${ordered.length} 台）`, '')
    for (const h of shown) lines.push(...renderHost(h))
  }
  if (!full && ordered.length > shown.length) {
    lines.push(`其余 ${ordered.length - shown.length} 台主机未展示。加 \`--out <报告.md>\` 生成完整报告后分段阅读。`, '')
  }
  if (r.upWithoutOpen.length) {
    lines.push(`存活但未发现开放端口：${listHosts(r.upWithoutOpen.map((h) => h.ip), 20)}`, '')
  }
  const globalScripts = [...r.scan.prescripts, ...r.scan.postscripts]
  if (globalScripts.length) {
    lines.push('全局脚本输出：')
    for (const sc of globalScripts) lines.push(`- ${sc.id}：${oneLine(sc.output, SCRIPT_OUTPUT_LIMIT)}`)
    lines.push('')
  }
  return lines.join('\n')
}

function toJson(r) {
  return {
    scan: r.scan,
    complete: r.complete,
    summary: {
      hostsUp: r.up.length,
      hostsWithOpenPorts: r.withOpen.length,
      openPorts: r.totalOpen,
      hints: r.hints,
      attention: r.attention.map(({ key, services, hosts, note }) => ({ port: key, services, hosts, note })),
    },
    hosts: r.hosts.map((h) => ({
      ip: h.ip, hostnames: h.hostnames, mac: h.mac, status: h.status, os: h.os, extraports: h.extraports, notes: h.notes,
      ports: h.ports.map((p) => ({
        port: p.portid, protocol: p.protocol, state: p.state, reason: p.reason,
        service: p.service, scripts: p.scripts, flags: p.flags, attention: p.attention,
      })),
      scripts: h.scripts,
    })),
  }
}

// ---------- 入口 ----------

function main(argv) {
  let opts
  try {
    opts = parseArgs(argv)
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`${e.message}\n\n${HELP}\n`)
      return 2
    }
    throw e
  }
  if (opts.help) {
    process.stdout.write(`${HELP}\n`)
    return 0
  }
  let xml
  try {
    xml = readText(opts.file)
  } catch (e) {
    process.stderr.write(`无法读取文件：${opts.file}（${e.code ?? e.message}）\n`)
    return 1
  }
  const parsed = parseNmapXml(xml)
  if (!parsed.sawRoot) {
    process.stderr.write('这不是 Nmap XML（没有找到 <nmaprun>）。如果是 -oN 普通输出或其他工具的报告，请直接阅读文件。\n')
    return 1
  }
  const r = analyze(parsed)
  const label = basename(opts.file)
  if (opts.json) {
    process.stdout.write(`${JSON.stringify(toJson(r), null, 2)}\n`)
    return 0
  }
  if (opts.out) {
    writeFileSync(opts.out, `${renderMarkdown(r, label, { maxHosts: Infinity, full: true })}\n`, 'utf8')
    const overview = renderOverview(r, label)
    overview.push(`完整报告（${r.withOpen.length} 台有开放端口的主机明细）已写入：${opts.out}`)
    process.stdout.write(`${overview.join('\n')}\n`)
    return 0
  }
  process.stdout.write(`${renderMarkdown(r, label, { maxHosts: opts.maxHosts, full: false })}\n`)
  return 0
}

function invokedDirectly() {
  if (!process.argv[1]) return false
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))
  } catch {
    return false
  }
}

if (invokedDirectly()) {
  process.exitCode = main(process.argv.slice(2))
}
