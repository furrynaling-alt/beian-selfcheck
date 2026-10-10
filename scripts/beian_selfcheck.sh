#!/bin/bash
# ============================================================================
#  服务器合规自查 · 一键脚本（只读、不装任何东西、不改任何配置）
#  用法：  bash compliance_check.sh            # 人看的报告
#          bash compliance_check.sh --md       # 直接出 Markdown 表格
#  说明：  每条都打印【命令 + 结果 + 判定】。判定口径写在每段注释里。
#          只做"发现"，不做"处置" —— 发现什么由人决定。
# ============================================================================
MD=0; HTML=0
[ "$1" = "--md" ] && MD=1
[ "$1" = "--html" ] && HTML=1
HOST=$(hostname 2>/dev/null); OS=$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")
NOW=$(date '+%F %T')
HIT=0; MISS=0
declare -a ROWS

say() { [ "$MD" = "0" ] && echo "$@"; }
rec() { # 序号|名称|状态|明细|日志
  ROWS+=("$1	$2	$3	$4	$5")
  [ "$3" = "检出" ] && HIT=$((HIT+1)) || MISS=$((MISS+1))
  if [ "$MD" = "0" ]; then
    printf '%-4s %-22s %-6s %s\n' "$1" "$2" "$3" "$4"
    [ -n "$5" ] && printf '      日志: %s\n' "$5"
  fi
}

say "=========================================================="
say " 网站备案 / 服务器合规自检（只读）  主机: $HOST  系统: $OS"
say " 时间: $NOW"
say "=========================================================="

# ---- 1 代理/翻墙类进程 -------------------------------------------------
P=$(pgrep -a -f -i '(^|/)ss-server|sslocal|ssr-server|v2ray|xray|trojan|(^|/)tor($| )|wireguard|wg-quick|openvpn|hysteria|sing-box|clash|gost|frps|frpc|(^|/)nps' 2>/dev/null | grep -v compliance_check | head -5)
if [ -n "$P" ]; then rec 1 "代理/翻墙类进程" "检出" "发现代理类进程" "$(echo "$P" | head -2 | tr '\n' ';')"
else rec 1 "代理/翻墙类进程" "未检出" "无匹配进程"; fi

# ---- 2 特征端口 / 无主进程的高位监听 -----------------------------------
PORTS=$(ss -tlnp 2>/dev/null | awk 'NR>1 && ($4 ~ /^0\.0\.0\.0:/ || $4 ~ /^\[::\]:/) {print $4}' | sed 's/.*://' | sort -un | tr '\n' ' ')
FEAT=""
for p in 1080 8388 8443 2053 2083 2087 2096 9115 10086 3128 8889; do
  [ -n "$PORTS" ] && echo " $PORTS " | grep -q " $p " && FEAT="$FEAT $p"
done
if [ -n "$FEAT" ]; then rec 2 "特征端口监听" "检出" "公网监听命中特征端口：$FEAT" "ss -tlnp → $PORTS"
else rec 2 "特征端口监听" "未检出" "公网监听：${PORTS:-（无）}"; fi

# ---- 3 代理类配置目录 --------------------------------------------------
D=$(ls -d /etc/shadowsocks* /etc/v2ray /etc/xray /etc/trojan* /etc/wireguard /etc/sing-box /etc/clash /etc/openvpn /usr/local/etc/v2ray 2>/dev/null | tr '\n' ' ')
if [ -n "$D" ]; then rec 3 "代理类配置目录" "检出" "存在配置目录：$D" "$D"
else rec 3 "代理类配置目录" "未检出" "无常见代理配置目录"; fi

# ---- 4 开机自启里的代理类 + 拉起脚本 -----------------------------------
U=$(systemctl list-unit-files --state=enabled 2>/dev/null | awk '{print $1}' | grep -iE 'tor|v2ray|xray|trojan|shadowsocks|wireguard|openvpn|sing-box|hysteria|clash' | tr '\n' ' ')
R=$(ls -la /etc/rc.local 2>/dev/null; crontab -l 2>/dev/null | grep -iE 'tor|v2ray|xray|trojan|ss-server|wireguard|clash|sing-box' | head -3)
if [ -n "$U" ] || [ -n "$R" ]; then rec 4 "自启/定时拉起代理" "检出" "enabled 单元：${U:-无}；crontab/rc.local 命中：有" "$U $R"
else rec 4 "自启/定时拉起代理" "未检出" "enabled 单元与 crontab 均无命中"; fi

# ---- 5 PCDN / 流量转卖 -------------------------------------------------
P5=$(pgrep -a -f -i 'pcdn|网心云|玩客云|赚钱宝|wxy|onething|jdcnode|xycdn' 2>/dev/null | head -3)
if [ -n "$P5" ]; then rec 5 "PCDN/流量转卖" "检出" "发现相关进程" "$P5"
else rec 5 "PCDN/流量转卖" "未检出" "无相关进程"; fi

# ---- 6 发卡 / 支付类可疑服务 -------------------------------------------
echo "6	发卡/支付类可疑服务" >>/dev/null
P6=$( (ls -d /www/wwwroot/*faka* /www/wwwroot/*epay* /www/wwwroot/*pay* 2>/dev/null; grep -rliE '发卡|epay|码支付|四方支付' /etc/nginx/sites-enabled/ /etc/nginx/conf.d/ 2>/dev/null) | head -4)
if [ -n "$P6" ]; then rec 6 "发卡/支付类可疑服务" "检出" "站点或配置命中" "$P6"
else rec 6 "发卡/支付类可疑服务" "未检出" "未发现自建发卡/支付系统"; fi

# ---- 7 赌黄诈/私服/外挂站点 --------------------------------------------
P7=$(grep -rliE '百家乐|博彩|棋牌|六合彩|色情|成人视频|私服|外挂|代练|刷单|跑分' /www/wwwroot /var/www 2>/dev/null | grep -viE 'privacy|terms|policy|agreement|abnormal|安全|声明|license' | head -4)
if [ -n "$P7" ]; then rec 7 "赌黄诈/私服外挂站点" "检出" "站点文件命中关键词" "$(echo "$P7" | head -2)"
else rec 7 "赌黄诈/私服外挂站点" "未检出" "站点目录未见命中"; fi

# ---- 8 盗版/侵权分发（公网）-------------------------------------------
P8=$(find /www/wwwroot /var/www -maxdepth 3 -type d \( -iname '*movie*' -o -iname '*mv*' -o -iname '*torrent*' -o -iname '*影视*' -o -iname '*download*' \) 2>/dev/null | head -4)
if [ -n "$P8" ]; then rec 8 "盗版/侵权内容分发" "检出" "疑似分发目录（需人工确认）" "$(echo "$P8" | head -2)"
else rec 8 "盗版/侵权内容分发" "未检出" "未发现疑似盗版分发目录"; fi

# ---- 9 站点内容关键词（涉政/涉黄/涉赌/涉诈）---------------------------
P9=$(grep -rliE '赌博|博彩|色情|裸聊|诈骗|洗钱|发票代开|办证|假证' /www/wwwroot /var/www 2>/dev/null | grep -viE 'privacy|terms|policy|agreement|abnormal|安全|声明|license' | head -4)
if [ -n "$P9" ]; then rec 9 "站点内容关键词" "检出" "命中，需人工复核是否误报" "$(echo "$P9" | head -2)"
else rec 9 "站点内容关键词" "未检出" "站点正文无命中"; fi

# ---- 10 未备案对外提供 web 服务 ----------------------------------------
echo "10	未备案对外提供 web 服务" >>/dev/null
SITES=$(grep -rhoE 'server_name[^;]+;' /etc/nginx/sites-enabled/ /etc/nginx/conf.d/ 2>/dev/null | sed 's/server_name//;s/;//' | tr -s ' ' '\n' | grep -vE '^$|^_$|localhost' | sort -u | tr '\n' ' ')
IPCN=$([ -f /etc/nginx/nginx.conf ] && echo yes)
# 判断机器是否在境内：能拿到公网 IP 时查归属，拿不到就跳过（不联网推断）
PUBIP=$(curl -s -m 6 https://ipinfo.io/ip 2>/dev/null || curl -s -m 6 ifconfig.me 2>/dev/null)
CTRY=$(curl -s -m 6 "http://ip-api.com/json/$PUBIP?fields=country" 2>/dev/null | sed -E 's/.*"country":"([^"]*)".*/\1/')
if [ -n "$SITES" ]; then
  if [ "$CTRY" = "China" ]; then
    rec 10 "未备案对外提供 web" "检出" "境内机器 + 对外站点：$SITES（需逐域名核 ICP 备案）" "nginx server_name: $SITES"
  else
    rec 10 "未备案对外提供 web" "未检出" "机器在【${CTRY:-未知}】—— 境外服务器不适用 ICP 备案；站点：$SITES"
  fi
else rec 10 "未备案对外提供 web" "未检出" "未发现对外站点（或不用 nginx）"; fi

# ---- 11 上传/评论接口被滥用 -------------------------------------------
UP=$(find /www/wwwroot /var/www /srv -maxdepth 4 -type d -iname 'upload*' 2>/dev/null | head -3)
UPX=""
for d in $UP; do UPX="$UPX $(find "$d" -maxdepth 2 -type f \( -name '*.php' -o -name '*.jsp' -o -name '*.sh' \) 2>/dev/null | head -3)"; done
if [ -n "$(echo $UPX | tr -d ' ')" ]; then rec 11 "上传目录可执行文件" "检出" "上传目录内有脚本（webshell 风险）" "$UPX"
else rec 11 "上传目录可执行文件" "未检出" "上传目录未见脚本文件"; fi

# ---- 12 他人个人信息文件 ----------------------------------------------
PI=""
for f in $(grep -rlsE '[1-9][0-9]{5}(19|20)[0-9]{2}(0[1-9]|1[0-2])[0-9]{4}' /root /home /srv /data /opt 2>/dev/null --include='*.csv' --include='*.txt' --include='*.json' --include='*.xlsx' --exclude-dir=.hermes --exclude-dir=.cache | head -20); do
  n=$(grep -cE '[1-9][0-9]{5}(19|20)[0-9]{2}(0[1-9]|1[0-2])[0-9]{4}' "$f" 2>/dev/null)
  [ "${n:-0}" -ge 100 ] && PI="$PI $f(${n}条)"
done
if [ -n "$PI" ]; then rec 12 "成批个人信息文件" "检出" "疑似含身份证号的文件（需人工确认）" "$(echo "$PI" | head -3)"
else rec 12 "成批个人信息文件" "未检出" "常见目录未见成批身份证号特征"; fi

# ---- 13 日志留存 ------------------------------------------------------
L6=0
for d in /var/log; do
  oldest=$(find "$d" -type f -name '*.log*' -printf '%TY-%Tm\n' 2>/dev/null | sort | head -1)
  echo "$oldest" | grep -qE '^(20[0-9]{2})-(0[1-9]|1[0-2])$' && L6=1
done
RB=$(grep -rlE 'logrotate' /etc/logrotate.d/* 2>/dev/null | head -1)
[ "$L6" = "1" ] && rec 13 "日志留存≥6个月" "未检出" "存在跨月日志（仍建议核实是否满 6 个月）" "logrotate: ${RB:-未配置}" \
                || rec 13 "日志留存≥6个月" "检出" "日志未见跨月留存，约不足 6 个月" "logrotate: ${RB:-未配置}"

# ---- 14 明文密钥/口令 --------------------------------------------------
K=$(grep -rlsE '(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|(password|passwd|pwd)\s*[:=]\s*[^ ]{6,})' /root /etc /opt /www 2>/dev/null --include='*.sh' --include='*.py' --include='*.conf' --include='*.yaml' --include='*.yml' --include='*.env' --include='*.txt' | grep -viE 'example|sample|placeholder|\.bak' | head -5)
if [ -n "$K" ]; then rec 14 "明文密钥/口令" "检出" "疑似明文凭据文件（需人工确认是否已吊销）" "$(echo "$K" | head -3)"
else rec 14 "明文密钥/口令" "未检出" "常见配置未见明文凭据特征"; fi

# ---- 15 破解软件/激活工具/非官方镜像 -----------------------------------
C=$(find / -xdev -maxdepth 4 \( -iname '*kms*' -o -iname '*activator*' -o -iname '*keygen*' -o -iname '*crack*' -o -iname '*破解*' \) -not -path '/usr/*' -not -path '/lib/*' -not -path '/etc/systemd/*' -not -path '*/node_modules/*' 2>/dev/null | head -4)
IMG=$(find / -xdev -maxdepth 3 \( -iname '*.esd' -o -iname '*win*ghost*' -o -iname '*GHO' \) 2>/dev/null | head -3)
if [ -n "$C" ] || [ -n "$IMG" ]; then rec 15 "破解工具/非官方镜像" "检出" "破解类文件：${C:-无}；镜像类：${IMG:-无}" "$C $IMG"
else rec 15 "破解工具/非官方镜像" "未检出" "未见破解/激活/改版镜像文件"; fi

# ---- 16 模板/源码授权（弱信号，只提示）--------------------------------
T=$(find /www /srv /opt -maxdepth 4 -type f \( -name '*.theme' -o -iname '*template*商業*' \) 2>/dev/null | head -3)
rec 16 "模板/源码授权" "未检出" "无法自动判断授权，需人工核对（开源许可/采购凭证）" "建议人工"

# ---- 17 群发特征与退订入口 --------------------------------------------
M=$(grep -rliE 'mass_?mail|bulk_?send|群发' /root /opt /www 2>/dev/null --include='*.sh' --include='*.py' | grep -viE 'audit|evidence|审计|日志|compliance_check' | head -3)
if [ -n "$M" ]; then rec 17 "群发/无退订入口" "检出" "存在群发脚本（需确认退订入口与频率）" "$(echo "$M" | head -2)"
else rec 17 "群发/无退订入口" "未检出" "未见群发脚本"; fi

# ---- 18 发件人伪造 / SPF-DKIM-DMARC -----------------------------------
echo "18	发件人伪造/邮件鉴权" >>/dev/null
DOMS=$(grep -rhoE 'server_name[^;]+;' /etc/nginx/sites-enabled/ /etc/nginx/conf.d/ 2>/dev/null | sed 's/server_name//;s/;//' | tr -s ' ' '\n' | grep -E '\.' | sort -u | head -5)
NOAUTH=""
for d in $DOMS; do
  spf=$(timeout 5 dig +short TXT "$d" 2>/dev/null | grep -c 'v=spf1')
  [ "$spf" = "0" ] && NOAUTH="$NOAUTH $d"
done
if [ -n "$(echo $NOAUTH | tr -d ' ')" ]; then rec 18 "发件人伪造/邮件鉴权" "检出" "以下域名无 SPF：$NOAUTH（仅当该域名对外发信才有意义，人工复核）" "dig TXT $NOAUTH"
else rec 18 "发件人伪造/邮件鉴权" "未检出" "已抽查域名 SPF 存在（DKIM/DMARC 需另查）"; fi

# ---- 19 退信率 / 黑名单 ------------------------------------------------
BL=""
for d in $DOMS; do
  code=$(timeout 6 curl -s -o /dev/null -w '%{http_code}' "https://check.spamhaus.org/query/domain/$d/" 2>/dev/null)
  [ "$code" = "000" ] && continue
done
rec 19 "退信率/黑名单" "未检出" "无退信日志可查（脚本不代查第三方黑名单，建议人工查 Spamhaus DBL）" "建议人工"

say ""
say "----------------------------------------------------------"
say " 合计：检出 $HIT 项 / 未检出 $MISS 项　（判定口径见脚本注释）"
say " 提醒：本脚本只做「发现」，不自动处置；命中项请人工复核后处理。"
say "----------------------------------------------------------"

if [ "$MD" = "1" ]; then
  echo ""
  echo "| 序号 | 名称 | 状态 | 明细 | 日志/证据 |"
  echo "|---|---|---|---|---|"
  for r in "${ROWS[@]}"; do
    IFS=$'\t' read -r a b c d e <<<"$r"
    echo "| $a | $b | $c | $d | \`${e:-—}\` |"
  done
fi

if [ "$HTML" = "1" ]; then
  cat <<'HEAD'
<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>网站备案 / 服务器合规自检报告</title>
<style>
 body{font:15px/1.7 -apple-system,"PingFang SC","Microsoft YaHei",sans-serif;margin:0;background:#f6f7f9;color:#222}
 .wrap{max-width:1080px;margin:0 auto;padding:28px 18px 60px}
 h1{font-size:20px;margin:0 0 4px} .sub{color:#888;font-size:13px;margin-bottom:18px}
 table{border-collapse:collapse;width:100%;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 10px rgba(0,0,0,.06)}
 th,td{border-bottom:1px solid #eceff3;padding:9px 11px;font-size:13.5px;text-align:left;vertical-align:top}
 th{background:#f0f3f8;font-weight:600;white-space:nowrap}
 tr:last-child td{border-bottom:0}
 .hit{color:#d0021b;font-weight:700}      /* 检出：标红 */
 .miss{color:#8a94a6}
 .lv{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:700}
 .lv-SP,.lv-S,.lv-A{background:#fde8ea;color:#d0021b}
 .lv-B,.lv-C{background:#fff4e0;color:#a56000}
 .lv-D,.lv-E,.lv-F{background:#eef2f7;color:#5a6a80}
 .lv---{background:#f4f5f7;color:#9aa3b2}
 code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;color:#444;word-break:break-all}
</style></head><body><div class="wrap">
HEAD
  echo "<h1>网站备案 / 服务器合规自检报告</h1>"
  echo "<div class="sub">主机 $HOST · $OS · $NOW · 只读自查，检出项已标红</div>"
  echo "<table><tr><th>#</th><th>名称</th><th>状态</th><th>级别</th><th>明细</th><th>日志 / 证据</th></tr>"
  i=0
  for r in "${ROWS[@]}"; do
    i=$((i+1))
    IFS=$'	' read -r a b c d e <<<"$r"
    case "$c" in 检出) cls=hit;; *) cls=miss;; esac
    lv=$(printf '%s' "$d" | grep -oE '^[SABC][+A-F]|^--' | head -1)
    printf '<tr><td>%s</td><td>%s</td><td class="%s">%s</td><td><span class="lv lv-%s">%s</span></td><td>%s</td><td><code>%s</code></td></tr>
' \
      "$a" "$b" "$cls" "$c" "${lv:-F}" "${lv:-F}" "$d" "${e:-—}"
  done
  echo "</table>"
  echo "<p class="sub">合计：检出 $HIT 项 / 未检出 $MISS 项。本工具只做「发现」，不自动处置。</p></div></body></html>"
fi
