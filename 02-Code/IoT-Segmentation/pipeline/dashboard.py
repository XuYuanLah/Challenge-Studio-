"""Splunk content for the iot_segmentation app: detection macros (rules R1-R12 and two extras) and the
overview dashboard (Simple XML, dark theme). Imported by iotpipe.py's `app` step; no site-specific values.

Every rule macro returns the same columns, so the dashboard can stack them:
  _time  rule  rule_name  severity  device  device_role  capture  detail  count
Severities: critical > high > medium > low > info (info = expected / policy, shown for completeness).
"""

SEVERITY_COLORS = {'critical': '#DC4E41', 'high': '#F1813F', 'medium': '#F8BE34', 'low': '#1182F3', 'info': '#53A051'}

# rule id -> (plain-language name, severity rationale). Shown in the dashboard's legend.
RULES = [
    ('R1', 'New domain for a device', 'low', 'a domain the device never looked up during a baseline recording'),
    ('R2', 'Tried to reach the main network', 'critical / info', 'blocked by the firewall; info when it is a Matter status message to a controller (policy, rec. 22)'),
    ('R3', 'Unusual data volume', 'medium to critical', 'more than 10x the device\'s normal hourly internet traffic (floor 10 kB/h, rec. 20); severity grows with the ratio'),
    ('R4', 'Traffic to an impossible address', 'high', 'sent to an address that cannot exist on the internet (e.g. the SwitchBot leak to 255.2.0.0)'),
    ('R5', 'Keeps retrying a blocked domain', 'medium', 'blocked DNS lookups per hour above 5x the first baseline'),
    ('R6', 'Burst of connections', 'medium', 'more than 10 new connections to one internet server within 10 minutes'),
    ('R7', 'Asked a DNS server other than Pi-hole', 'high / medium', 'high if it reached an outside resolver, medium if the router redirected it to Pi-hole'),
    ('R8', 'Local-only device talked to the internet', 'critical', 'a device marked local_only (the Matter switches) contacted the internet'),
    ('R9', 'New encryption fingerprint', 'low', 'a TLS client fingerprint (JA4) not seen during a baseline: new software or a reboot'),
    ('R10', 'Unencrypted web traffic to the internet', 'high', 'plain HTTP to the internet: anyone on the path can read it'),
    ('R11', 'Router stopped advertising IPv6', 'medium', 'no IPv6 router advertisement for 3 minutes or more during a recording'),
    ('R12', 'Outdated encryption', 'medium', 'TLS older than 1.2'),
    ('FW', 'Tried a blocked router service', 'high', 'an IoT-side host tried a router service it may not use (state E hardening)'),
    ('DEV', 'Unexpected device on the IoT network', 'high / medium', 'a device not in the inventory, a controller or a personal device joined the IoT segment'),
]

M = {}
M['iot_det_r1'] = r'''`iot_index` (sourcetype=iot:pihole OR sourcetype=iot:dns) device_role=iot query=*
| lookup iot_devices mac AS device_mac OUTPUT baselined
| where baselined="true"
| lookup iot_captures capture OUTPUT baseline
| eval in_base=if(baseline="true",1,0)
| eventstats max(in_base) AS seen_in_baseline BY device query
| where seen_in_baseline=0
| fillnull value="(no recording)" capture
| stats min(_time) AS _time count BY device device_role capture query
| eval rule="R1", rule_name="New domain for a device", severity="low", detail="Looked up ".query." (not seen in any baseline)"'''

M['iot_det_r2'] = r'''`iot_index` sourcetype=iot:fw log_prefix=IOT_TO_LAN_DROP
| fillnull value="" dest_name
| fillnull value="(no recording)" capture
| eval matter=if(src_port=5540 AND dest_name!="", 1, 0), target=if(dest_name!="", dest_name." (".dest_ip.")", dest_ip)
| stats min(_time) AS _time count values(dest_port) AS ports BY device device_role capture target matter
| eval rule="R2", rule_name=if(matter=1, "Matter status message blocked (expected)", "Tried to reach the main network"), severity=if(matter=1, "info", "critical"), detail=if(matter=1, "Matter report to ".target." blocked (connection state lost, see rec. 22)", "Blocked attempt to ".target." on port(s) ".mvjoin(ports, ", "))'''

M['iot_det_r3'] = r'''`iot_index` sourcetype=iot:volume
| bin _time span=1h
| stats sum(out_wan) AS out_wan sum(in_wan) AS in_wan BY _time device device_role capture
| lookup iot_captures capture OUTPUT baseline
| eventstats median(eval(if(baseline="true" AND out_wan>0, out_wan, null()))) AS base_out median(eval(if(baseline="true" AND in_wan>0, in_wan, null()))) AS base_in BY device
| eventstats max(base_out) AS seg_out max(base_in) AS seg_in
| eval lim_out=if(isnull(base_out), 10*seg_out, max(10*base_out, 10000)), lim_in=if(isnull(base_in), 10*seg_in, max(10*base_in, 10000))
| eval r_out=round(coalesce(out_wan,0)/(lim_out/10), 1), r_in=round(coalesce(in_wan,0)/(lim_in/10), 1)
| where coalesce(out_wan,0) > lim_out OR coalesce(in_wan,0) > lim_in
| eval ratio=max(r_out, r_in), count=1
| eval rule="R3", rule_name="Unusual data volume", severity=case(ratio>=100, "critical", ratio>=30, "high", true(), "medium"), detail="Internet traffic in this hour: ".round(coalesce(out_wan,0)/1000000, 2)." MB up, ".round(coalesce(in_wan,0)/1000000, 2)." MB down (".ratio."x normal".if(isnull(base_out), ", no own baseline: compared with the busiest device", "").")"'''

M['iot_det_r4'] = r'''`iot_index` sourcetype=iot:conn peer_class=bogon initiated_by=device
| stats min(_time) AS _time count BY device device_role capture peer_ip
| eval rule="R4", rule_name="Traffic to an impossible address", severity="high", detail=count." packet flow(s) to ".peer_ip.", an address that cannot exist on the internet"'''

M['iot_det_r5'] = r'''`iot_index` sourcetype=iot:pihole blocked=true
| fillnull value="(no recording)" capture
| bin _time span=1h
| stats count AS per_hour BY _time device device_role capture
| lookup iot_captures capture OUTPUT baseline start
| eval bstart=if(baseline="true", start, null())
| eventstats min(bstart) AS ref_start
| eventstats median(eval(if(start=ref_start, per_hour, null()))) AS base BY device
| eval base=max(coalesce(base, 1), 1)
| where per_hour > 5*base
| stats min(_time) AS _time count max(per_hour) AS peak first(base) AS base BY device device_role capture
| eval rule="R5", rule_name="Keeps retrying a blocked domain", severity="medium", detail="Up to ".peak." blocked lookups per hour (normal: ".base."); ".count." hour(s) above 5x"'''

M['iot_det_r6'] = r'''`iot_index` sourcetype=iot:conn initiated_by=device proto=tcp peer_class=wan
| bin _time span=10m
| stats count AS conns BY _time device device_role capture peer_ip
| where conns > 10
| stats min(_time) AS _time count max(conns) AS peak BY device device_role capture peer_ip
| eval rule="R6", rule_name="Burst of connections", severity="medium", detail="Up to ".peak." new connections per 10 min to ".peer_ip." (".count." window(s))"'''

M['iot_det_r7'] = r'''`iot_index` ((sourcetype=iot:conn initiated_by=device (dest_port=53 OR dest_port=853) NOT peer_class=dns NOT peer_class=multicast) OR (sourcetype=iot:fw log_prefix=IOT_TO_WAN_NEW (dest_port=53 OR dest_port=853)) OR (sourcetype=iot:fw log_prefix=IOT_DNS_REDIRECT))
| fillnull value="(no recording)" capture
| eval redirected=if(log_prefix="IOT_DNS_REDIRECT", 1, 0), port=coalesce(dest_port, 0)
| stats min(_time) AS _time count BY device device_role capture dest_ip port redirected
| eval rule="R7", rule_name=if(redirected=1, "DNS to another server, redirected to Pi-hole", "Asked a DNS server other than Pi-hole"), severity=if(redirected=1, "medium", "high"), detail=if(redirected=1, "DNS to ".dest_ip." port ".port." was redirected to Pi-hole (prevented)", "DNS".if(port=853, "-over-TLS", "")." to ".dest_ip." (bypasses Pi-hole)")'''

M['iot_det_r8'] = r'''`iot_index` ((sourcetype=iot:conn peer_class=wan) OR (sourcetype=iot:fw log_prefix=IOT_TO_WAN_NEW))
| lookup iot_devices mac AS device_mac OUTPUT local_only
| where local_only="true"
| fillnull value="(no recording)" capture
| eval peer=coalesce(peer_ip, dest_ip)
| stats min(_time) AS _time count BY device device_role capture peer
| eval rule="R8", rule_name="Local-only device talked to the internet", severity="critical", detail="Contacted ".peer." although it should never use the internet"'''

M['iot_det_r9'] = r'''`iot_index` sourcetype=iot:tls_hello device_role=iot ja4=*
| lookup iot_devices mac AS device_mac OUTPUT baselined
| where baselined="true"
| lookup iot_captures capture OUTPUT baseline
| eval in_base=if(baseline="true",1,0)
| eventstats max(in_base) AS seen_in_baseline BY device ja4
| where seen_in_baseline=0
| fillnull value="" server_name
| stats min(_time) AS _time count values(server_name) AS servers BY device device_role capture ja4
| eval rule="R9", rule_name="New encryption fingerprint", severity="low", detail="TLS fingerprint ".ja4." (to ".mvjoin(servers, ", ").")"'''

M['iot_det_r10'] = r'''`iot_index` sourcetype=iot:http peer_class=wan
| stats min(_time) AS _time count first(uri) AS uri first(method) AS method BY device device_role capture host
| eval rule="R10", rule_name="Unencrypted web traffic to the internet", severity="high", detail=coalesce(method, "GET")." http://".host.coalesce(uri, "/")'''

M['iot_det_r11'] = r'''`iot_index` sourcetype=iot:health
| sort 0 capture iface _time
| eval silent=if(router_adverts=0, 1, 0)
| streamstats current=f last(silent) AS prev BY capture iface
| eval change=if(isnull(prev) OR prev!=silent, 1, 0)
| streamstats sum(change) AS run BY capture iface
| where silent=1
| stats min(_time) AS _time count AS minutes BY capture iface run
| where minutes >= 3
| eval device="Router (".iface.")", device_role="router", count=1
| eval rule="R11", rule_name="Router stopped advertising IPv6", severity="medium", detail="No IPv6 router advertisements on ".iface." for ".minutes." minutes"'''

M['iot_det_r12'] = r'''`iot_index` sourcetype=iot:tls version IN ("SSLv3", "TLSv10", "TLSv11")
| fillnull value="" server_name
| stats min(_time) AS _time count BY device device_role capture server_name version
| eval rule="R12", rule_name="Outdated encryption", severity="medium", detail=version." to ".if(server_name!="", server_name, "(no server name)")'''

M['iot_det_fw'] = r'''`iot_index` sourcetype=iot:fw log_prefix=IOT_TO_ROUTER_DROP
| fillnull value="(no recording)" capture
| eval port=coalesce(dest_port, 0)
| stats min(_time) AS _time count values(port) AS ports BY device device_role capture dest_ip
| eval rule="FW", rule_name="Tried a blocked router service", severity="high", detail="Blocked: router address ".dest_ip.", port(s) ".mvjoin(mvindex(ports, 0, 9), ", ").if(mvcount(ports)>10, " and ".(mvcount(ports)-10)." more", "")'''

M['iot_det_dev'] = r'''`iot_index` (sourcetype=iot:conn OR sourcetype=iot:fw OR sourcetype=iot:dhcp OR sourcetype=iot:volume) (device_role=unknown OR device_role=personal OR device_role=controller)
| fillnull value="(no recording)" capture
| stats min(_time) AS _time count BY device device_role capture
| eval rule="DEV", rule_name=case(device_role="unknown", "Unlisted device on the IoT network", device_role="controller", "Controller joined the IoT network", true(), "Personal device on the IoT network"), severity=if(device_role="personal", "medium", "high"), detail=case(device_role="unknown", "A MAC address that is not in the inventory", device_role="controller", "A controller (hub/phone) was found on the IoT side: configuration drift", true(), "A personal device joined the IoT Wi-Fi (e.g. through a synced passphrase)")'''

SHORT = {'R1': 'R1 New domain', 'R2': 'R2 Main network', 'R3': 'R3 Volume', 'R4': 'R4 Impossible address',
         'R5': 'R5 Blocked retries', 'R6': 'R6 Connection burst', 'R7': 'R7 DNS bypass', 'R8': 'R8 Local-only online',
         'R9': 'R9 New TLS fingerprint', 'R10': 'R10 Cleartext web', 'R11': 'R11 IPv6 adverts', 'R12': 'R12 Old TLS',
         'FW': 'FW Router service', 'DEV': 'DEV Unexpected device'}
_ORDER = ['iot_det_r1', 'iot_det_r2', 'iot_det_r3', 'iot_det_r4', 'iot_det_r5', 'iot_det_r6', 'iot_det_r7',
          'iot_det_r8', 'iot_det_r9', 'iot_det_r10', 'iot_det_r11', 'iot_det_r12', 'iot_det_fw', 'iot_det_dev']
M['iot_detections'] = (f'`{_ORDER[0]}`\n' + '\n'.join(f'| append [ search `{m}` ]' for m in _ORDER[1:]) + r'''
| eval capture=if(isnull(capture) OR capture="", "(no recording)", capture)
| fillnull value=1 count
| eval sev_num=case(severity="critical", 5, severity="high", 4, severity="medium", 3, severity="low", 2, true(), 1)
| eval origin=case(device_role="iot", "Real device", device_role="test", "Simulated (test host)", device_role="router", "Router", true(), "Other host")
| eval rule_label=rule.": ".rule_name, rule_short=case(''' + ', '.join(f'rule="{k}", "{v}"' for k, v in SHORT.items()) + ''', true(), rule)
| table _time rule rule_name rule_label rule_short severity sev_num device device_role origin capture detail count''')

# plain-language names for firewall log prefixes and peer classes (used by several panels)
M['iot_fw_label'] = r'''eval what=case(log_prefix="IOT_TO_LAN_DROP", "Blocked: main network", log_prefix="IOT_TO_ROUTER_DROP", "Blocked: router service", log_prefix="IOT_DNS_REDIRECT", "Redirected: DNS to Pi-hole", log_prefix="IOT_TO_WAN_NEW", "Logged: new internet connection", true(), log_prefix)'''
M['iot_peer_label'] = r'''eval talks_to=case(peer_class="wan", "Internet", peer_class="lan", "Main network", peer_class="dns", "Pi-hole (DNS)", peer_class="router", "Router", peer_class="iot", "Other IoT devices", peer_class="multicast" OR peer_class="broadcast" OR peer_class="linklocal", "Local discovery (multicast)", peer_class="bogon", "Impossible addresses", peer_class="own_public", "Own public address", true(), "Other")'''


def macros_conf(index):
    out = ['# Generated by pipeline/iotpipe.py (app step) from pipeline/dashboard.py.', '',
           f'[iot_index]\ndefinition = index={index}\niseval = 0\n']
    for name, spl in M.items():
        out.append(f'[{name}]\ndefinition = ' + ' \\\n'.join(l.rstrip() for l in spl.strip().splitlines()) + '\niseval = 0\n')
    return '\n'.join(out)


# ------------------------------------------------------------------------------------------- dashboard
FILTER = ('| where ("$cap$"="__all" OR capture="$cap$") AND ("$dev$"="__all" OR device="$dev$") '
          'AND ("$tests$"="yes" OR isnull(device_role) OR device_role!="test")')
SEV_COLORS = '{"critical":0xDC4E41,"high":0xF1813F,"medium":0xF8BE34,"low":0x1182F3,"info":0x53A051}'


def esc(s): return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def q(spl, base=None, time=True, sid=None):
    attrs = (f' id="{sid}"' if sid else '') + (f' base="{base}"' if base else '')
    t = '\n        <earliest>$tr.earliest$</earliest>\n        <latest>$tr.latest$</latest>' if time and not base else ''
    return f'      <search{attrs}>\n        <query><![CDATA[{spl}]]></query>{t}\n      </search>'


def opts(**o):
    return '\n'.join(f'      <option name="{k.replace("__", ".")}">{esc(str(v))}</option>' for k, v in o.items())


ANNOT = '''      <search type="annotation">
        <query><![CDATA[`iot_index` sourcetype=iot:annotation | eval annotation_label=label.": ".text, annotation_category=kind]]></query>
        <earliest>$tr.earliest$</earliest>
        <latest>$tr.latest$</latest>
      </search>'''


def single(title, spl, color, base=None, under=None, fmt=None, zero='0x3c444d', mode='block'):
    """Single value: `zero` colour when the value is 0, `color` above it. mode 'block' colours the background,
    'none' colours the number only."""
    o = dict(colorMode=mode, useColors='1', rangeValues='[0]', rangeColors=f'["{zero}","{color}"]',
             drilldown='none', showSparkline='0', showTrendIndicator='0')
    if under: o['underLabel'] = under
    if fmt: o.update(fmt)
    return f'    <panel>\n      <single>\n        <title>{esc(title)}</title>\n{q(spl, base)}\n{opts(**o)}\n      </single>\n    </panel>'


def chart(title, spl, kind, base=None, annotate=False, desc=None, height=None, **o):
    d = f'        <description>{esc(desc)}</description>\n' if desc else ''
    a = ('\n' + ANNOT) if annotate else ''
    oo = dict(charting__chart=kind, charting__drilldown='none', charting__legend__placement='bottom')
    if height: oo['height'] = height
    oo.update(o)
    return (f'    <panel>\n      <chart>\n        <title>{esc(title)}</title>\n{d}{q(spl, base)}{a}\n{opts(**oo)}\n'
            f'      </chart>\n    </panel>')


def table(title, spl, base=None, desc=None, rows=10, colors=None, **o):
    d = f'        <description>{esc(desc)}</description>\n' if desc else ''
    oo = dict(count=rows, drilldown='none', wrap='true', rowNumbers='false', dataOverlayMode='none')
    oo.update(o)
    fm = ''
    for field, palette in (colors or {}).items():
        fm += f'\n      <format type="color" field="{field}">\n        <colorPalette type="map">{esc(palette)}</colorPalette>\n      </format>'
    return f'    <panel>\n      <table>\n        <title>{esc(title)}</title>\n{d}{q(spl, base)}\n{opts(**oo)}{fm}\n      </table>\n    </panel>'


def html(content):
    return f'    <panel>\n      <html>\n{content}\n      </html>\n    </panel>'


def row(*panels, depends=None):
    dep = f' depends="{depends}"' if depends else ''
    return f'  <row{dep}>\n' + '\n'.join(panels) + '\n  </row>'


SEV_PALETTE = '{"critical":#DC4E41,"high":#F1813F,"medium":#F8BE34,"low":#1182F3,"info":#53A051}'


def build_view():
    det = f'`iot_detections`\n{FILTER}\n| where sev_num >= $min_sev$'
    legend = ''.join(f'<tr><td><b>{r}</b></td><td>{esc(n)}</td><td>{esc(s)}</td><td>{esc(w)}</td></tr>' for r, n, s, w in RULES)
    swatch = ' '.join(f'<span style="background:{c};color:#111;padding:2px 8px;border-radius:3px;font-weight:bold">{k.upper()}</span>'
                      for k, c in SEVERITY_COLORS.items())
    rows = []
    rows.append(row(html(f'''        <h2>What this dashboard shows</h2>
        <p>The smart-home devices live on their own network segment (the <b>IoT network</b>), separated from the household's computers (the <b>main network</b>).
        Their traffic was recorded at the router before and after the separation, together with the router's firewall log and the Pi-hole DNS log.
        Each recording is one <b>capture</b>; the configuration that was live is its <b>state</b> (A = one flat network … E = final, router locked down).</p>
        <p><b>Read it top to bottom:</b> the counters give the big picture; <b>Detections</b> lists everything the 12 transparent rules flagged;
        <b>What is normal</b> shows each device's usual behaviour; <b>Is the separation working</b> shows what the firewall stopped;
        <b>Do the devices still work</b> shows the controllers reaching them; <b>Data quality</b> shows what the evidence covers.
        Grey dashed markers on the time charts are the operator's notes (what was done, when).</p>
        <p>Severity: {swatch} &#160; Simulated attacks come from a <b>test host</b> standing in for a compromised device; switch them off with the filter above.</p>'''),
        html('''        <h2>Learning Contract metrics</h2>
        <table class="table table-chrome">
          <tr><th>#</th><th>Metric</th><th>Status</th><th>Where to look</th></tr>
          <tr><td>1</td><td>Every planned test scenario was run</td><td><b style="color:#53A051">Met</b></td><td>Data quality: recordings and notes</td></tr>
          <tr><td>2</td><td>At least 3 suspicious behaviours detected by transparent rules</td><td><b style="color:#53A051">Met</b></td><td>Detections (real devices and test host)</td></tr>
          <tr><td>3</td><td>Unauthorised access between the networks is blocked</td><td><b style="color:#53A051">Met</b></td><td>Is the separation working</td></tr>
          <tr><td>4</td><td>Required device functions still work</td><td><b style="color:#53A051">Met</b></td><td>Do the devices still work; function checklist 28/28 (E110)</td></tr>
          <tr><td>5</td><td>Every result backed by reproducible evidence</td><td><b style="color:#53A051">Met</b></td><td>results_to_evidence.md; evidence_manifest.md</td></tr>
        </table>
        <p style="font-size:11px;color:#999">Status from analysis.md §9. The evidence IDs (E01 … E111) are listed in evidence_manifest.md.</p>''')))
    # base search for all detection panels (post-processed below)
    base_det = f'''  <search id="det">
    <query><![CDATA[{det}]]></query>
    <earliest>$tr.earliest$</earliest>
    <latest>$tr.latest$</latest>
  </search>'''
    rows.append(row(
        single('IoT devices seen', f'`iot_index` sourcetype=iot:conn device_role=iot\n{FILTER}\n| stats dc(device) AS devices', '0x5a6b7d'),
        single('Recordings', '| inputlookup iot_captures | where "$cap$"="__all" OR capture="$cap$" | stats count', '0x5a6b7d'),
        single('Events analysed', f'`iot_index`\n{FILTER}\n| stats count', '0x5a6b7d'),
        single('Detections', '| stats sum(count) AS findings dc(rule) AS rules | fields findings', '0xF8BE34', base='det',
               under='at the selected severity', zero='0x53A051', mode='none'),
        single('High or critical', '| where sev_num >= 4 | stats sum(count) AS n', '0xF1813F', base='det', under='need a closer look',
               zero='0x53A051'),
        single('Blocked by the firewall', f'`iot_index` sourcetype=iot:fw action=blocked\n{FILTER}\n| stats count', '0xDC4E41',
               under='stopped at the boundary', zero='0x53A051')))
    rows.append(row(html('        <h2 style="margin:0">Detections</h2>\n        <p style="margin:0">Everything the transparent rules flagged. Each row of the detail table says in plain words what happened.</p>')))
    rows.append(row(
        chart('Detections by severity', '| stats sum(count) AS count BY severity', 'pie', base='det', height=380,
              charting__fieldColors=SEV_COLORS, charting__chart__showPercent='true'),
        chart('Detections by rule', '| chart sum(count) AS count over rule_short by severity', 'bar', base='det', height=380,
              charting__axisLabelsX__majorLabelVisibility='show',
              charting__fieldColors=SEV_COLORS, charting__chart__stackMode='stacked', charting__axisTitleX__text='Rule',
              charting__axisTitleY__text='Flagged events', charting__chart__showDataLabels='minmax'),
        chart('Devices with the most detections', '| chart sum(count) AS count over device by severity | addtotals | sort - Total | fields - Total | head 10',
              'bar', base='det', height=380, charting__axisLabelsX__majorLabelVisibility='show',
              charting__fieldColors=SEV_COLORS, charting__chart__stackMode='stacked',
              charting__axisTitleX__text='Device', charting__axisTitleY__text='Flagged events')))
    rows.append(row(
        chart('Detections per recording', '| lookup iot_captures capture OUTPUT state start | eval recording=if(isnull(state), capture, capture." (".state.")") | chart sum(count) AS count over recording by severity | sort recording',
              'column', base='det', desc='Which recording each finding comes from (state in brackets). "(no recording)" = firewall log only, e.g. the active tests.',
              charting__fieldColors=SEV_COLORS, charting__chart__stackMode='stacked', charting__axisTitleX__visibility='collapsed',
              charting__axisTitleY__text='Flagged events'),
        chart('Real devices vs simulated attacks', '| chart sum(count) AS count over origin by severity', 'bar', base='det',
              desc='Simulated = the test host playing a compromised device.',
              charting__fieldColors=SEV_COLORS, charting__chart__stackMode='stacked', charting__axisTitleX__visibility='collapsed',
              charting__axisTitleY__text='Flagged events')))
    rows.append(row(table('Detection details', '''| sort - sev_num - count
| eval When=strftime(_time, "%Y-%m-%d %H:%M")
| rename severity AS Severity, rule_label AS Rule, detail AS "What happened", device AS Device, origin AS Source, capture AS Recording, count AS Count
| table When Severity Rule "What happened" Device Source Recording Count''', base='det', rows=15,
        desc='Highest severity first. Click a column header to sort.', colors={'Severity': SEV_PALETTE})))
    rows.append(row(html('''        <h2 style="margin:0">What is normal for each device</h2>
        <p style="margin:0">The baseline: who each device talks to and how much. Rules R1, R3, R5 and R9 compare new traffic with the baseline recordings.</p>''')))
    rows.append(row(
        chart('Internet upload per device (bytes per hour, log scale)',
              f'`iot_index` sourcetype=iot:volume\n{FILTER}\n| timechart span=1h sum(out_wan) BY device', 'line', annotate=True,
              desc='Data each device sent to the internet. Spikes are uploads; flat lines are routine check-ins.',
              charting__axisY__scale='log', charting__chart__nullValueMode='gaps', charting__axisTitleX__visibility='collapsed',
              charting__axisTitleY__text='Bytes per hour'),
        chart('Who each device talks to (share of its traffic)',
              f'`iot_index` sourcetype=iot:conn\n{FILTER}\n| `iot_peer_label`\n| eval bytes=bytes_out+bytes_in\n| chart sum(bytes) over device by talks_to',
              'bar', desc='By bytes. "Local discovery" is multicast that never leaves the house.',
              charting__chart__stackMode='stacked100', charting__axisTitleX__visibility='collapsed', charting__axisTitleY__text='% of bytes')))
    rows.append(row(table('Device profiles', f'''`iot_index` sourcetype=iot:conn
{FILTER}
| stats dc(eval(if(peer_class="wan", peer_ip, null()))) AS internet_servers count AS connections count(eval(initiated_by="peer")) AS started_by_others values(capture) AS recordings BY device device_mac device_role
| join type=left device [ search `iot_index` sourcetype=iot:volume
    {FILTER}
    | bin _time span=1h | stats sum(out_wan) AS up sum(in_wan) AS down BY _time device
    | stats median(up) AS med_up median(down) AS med_down BY device ]
| join type=left device [ search `iot_index` (sourcetype=iot:pihole OR sourcetype=iot:dns)
    {FILTER}
    | stats dc(query) AS domains BY device ]
| lookup iot_devices mac AS device_mac OUTPUT type local_only baselined
| eval up_txt=if(isnull(med_up), "none", round(med_up/1000, 1)." kB"), down_txt=if(isnull(med_down), "none", round(med_down/1000, 1)." kB")
| eval Recordings=mvjoin(recordings, ", "), lo=if(local_only="true", "yes", "no"), Baselined=if(baselined="true", "yes", "no")
| fillnull value=0 domains
| rename device AS Device, type AS Type, internet_servers AS "Internet servers", domains AS "Domains looked up", connections AS Connections, started_by_others AS "Started by others", device_role AS Role, up_txt AS "Internet upload / h (median)", down_txt AS "Internet download / h (median)", lo AS "Local only"
| table Device Type Role "Local only" Baselined "Internet servers" "Domains looked up" "Internet upload / h (median)" "Internet download / h (median)" Connections "Started by others" Recordings''',
        desc='One line per device: its normal footprint. "Started by others" are connections a controller or another host opened to the device.', rows=12)))
    rows.append(row(html('''        <h2 style="margin:0">Is the separation working?</h2>
        <p style="margin:0">What the router's firewall stopped, and who could reach the devices before and after the separation.</p>''')))
    rows.append(row(
        chart('What the firewall did', f'`iot_index` sourcetype=iot:fw\n{FILTER}\n| `iot_fw_label`\n| eval origin=case(device_role="iot", "Real device", device_role="test", "Test host", true(), "Other host")\n| chart count over what by origin',
              'bar', height=320, desc='Logged = allowed but recorded. Blocked and redirected = stopped at the boundary. Log scale.',
              charting__axisY__scale='log', charting__axisLabelsX__majorLabelVisibility='show', charting__axisTitleX__visibility='collapsed',
              charting__axisTitleY__text='Log entries', charting__chart__showDataLabels='minmax'),
        chart('Hosts that started connections to IoT devices', f'`iot_index` sourcetype=iot:conn initiated_by=peer\n{FILTER}\n| `iot_peer_label`\n| eval recording=capture." (".state.")"\n| chart dc(peer_ip) AS hosts over recording by talks_to',
              'column', desc='Before the separation (state A) many household hosts reached the devices; afterwards only the controllers.',
              charting__chart__stackMode='stacked', charting__axisTitleX__visibility='collapsed', charting__axisTitleY__text='Distinct hosts')))
    rows.append(row(table('Blocked attempts by destination', f'''`iot_index` sourcetype=iot:fw action!=logged
{FILTER}
| `iot_fw_label`
| fillnull value="" dest_name
| eval Destination=if(dest_name!="", dest_name." (".dest_ip.")", dest_ip), port=coalesce(dest_port, "-")
| stats count AS Attempts values(port) AS Ports min(_time) AS first max(_time) AS last BY device device_role what Destination
| eval Ports=mvjoin(mvindex(Ports, 0, 7), ", ").if(mvcount(Ports)>8, " …", ""), first_txt=strftime(first, "%Y-%m-%d %H:%M"), last_txt=strftime(last, "%Y-%m-%d %H:%M")
| sort - Attempts
| rename device AS Device, device_role AS Role, what AS What, first_txt AS "First seen", last_txt AS "Last seen"
| table Device Role What Destination Ports Attempts "First seen" "Last seen"''', rows=10,
        desc='Every blocked or redirected attempt from the IoT side, grouped by target.')))
    rows.append(row(html('''        <h2 style="margin:0">Do the devices still work?</h2>
        <p style="margin:0">Controllers (HomePod, iPhone, Mac) reach the devices over Matter (UDP 5540), and the devices get their DNS answers from Pi-hole.
        The full 28-point function checklist passed in the final state (evidence E110, E111).</p>''')))
    rows.append(row(
        chart('Controller sessions per device (Matter)', f'`iot_index` sourcetype=iot:conn initiated_by=peer (dest_port=5540 OR src_port=5540)\n{FILTER}\n| eval controller=if(isnull(peer_name) OR peer_name="", peer_ip, peer_name)\n| chart count over device by controller',
              'bar', desc='Matter connections a controller opened to each device, across the selected recordings.',
              charting__chart__stackMode='stacked', charting__axisTitleX__visibility='collapsed', charting__axisTitleY__text='Sessions'),
        chart('DNS answers for the devices (Pi-hole)', f'`iot_index` sourcetype=iot:pihole\n{FILTER}\n| eval answer=if(blocked="true", "Blocked (tracking / telemetry)", "Answered")\n| chart count over device by answer',
              'bar', desc='Blocked lookups are telemetry domains on the block list, e.g. the Hue diagnostics host.',
              charting__chart__stackMode='stacked', charting__fieldColors='{"Answered":0x53A051,"Blocked (tracking / telemetry)":0xDC4E41}',
              charting__axisTitleX__visibility='collapsed', charting__axisTitleY__text='Queries')))
    rows.append(row(html('''        <h2 style="margin:0">Data quality and coverage</h2>
        <p style="margin:0">What the evidence covers: the recordings, the operator's notes and the health of the capture.</p>''')))
    rows.append(row(
        table('Recordings', '''| inputlookup iot_captures
| where "$cap$"="__all" OR capture="$cap$"
| eval Baseline=if(baseline="true", "yes", "no"), Hours=round((end-start)/3600, 1)
| rename capture AS Recording, state AS State, start_local AS Start, end_local AS End, description AS "What it is"
| table Recording State Baseline Start End Hours "What it is"''', rows=8),
        table('Operator notes (ground truth)', '''`iot_index` sourcetype=iot:annotation
| where "$cap$"="__all" OR capture="$cap$" OR isnull(capture) OR capture=""
| sort _time
| eval When=strftime(_time, "%Y-%m-%d %H:%M")
| rename kind AS Kind, label AS What, text AS Details, capture AS Recording
| table When Recording Kind What Details''', rows=8)))
    rows.append(row(
        chart('IPv6 router advertisements (capture health, R11)', '`iot_index` sourcetype=iot:health\n| where "$cap$"="__all" OR capture="$cap$"\n| timechart span=5m sum(router_adverts) BY iface',
              'column', annotate=True, desc='About 7 per minute is normal. A run of zeros during a recording means the router stopped advertising IPv6.',
              charting__axisTitleX__visibility='collapsed', charting__axisTitleY__text='Adverts per 5 min', charting__chart__nullValueMode='gaps'),
        table('Events per data source', f'''`iot_index`
{FILTER}
| stats count BY sourcetype
| eval Source=case(sourcetype="iot:conn", "Connections (Zeek)", sourcetype="iot:dns", "DNS on the wire (Zeek)", sourcetype="iot:tls", "TLS sessions (Zeek)", sourcetype="iot:tls_hello", "TLS fingerprints (tshark)", sourcetype="iot:http", "Plain HTTP (Zeek)", sourcetype="iot:dhcp", "DHCP (Zeek)", sourcetype="iot:volume", "Volume per device-minute (pcap)", sourcetype="iot:health", "Capture health per minute (pcap)", sourcetype="iot:fw", "Router firewall log", sourcetype="iot:pihole", "Pi-hole DNS log", sourcetype="iot:annotation", "Operator notes", true(), sourcetype)
| rename sourcetype AS Sourcetype, count AS Events
| table Source Sourcetype Events''', rows=11, desc='Totals should match pipeline_out/prepare_report.json when no filter is set.')))
    rows.append(row(html(f'''        <h2>The rules</h2>
        <p>Each rule is one plain condition with a fixed threshold, so anyone can check why it fired. Full definitions: analysis.md §8; one-line versions: results_to_evidence.md.
        The searches are the macros <code>iot_det_r1</code> … <code>iot_det_r12</code>, <code>iot_det_fw</code>, <code>iot_det_dev</code> in this app.</p>
        <table class="table table-chrome"><tr><th>Rule</th><th>Name</th><th>Severity</th><th>Fires when</th></tr>{legend}</table>''')))
    fieldset = '''  <fieldset submitButton="false" autoRun="true">
    <input type="time" token="tr" searchWhenChanged="true">
      <label>Time range</label>
      <default>
        <earliest>0</earliest>
        <latest></latest>
      </default>
    </input>
    <input type="dropdown" token="cap" searchWhenChanged="true">
      <label>Recording</label>
      <choice value="__all">All recordings</choice>
      <search>
        <query><![CDATA[| inputlookup iot_captures | eval label=capture." (state ".state.", ".start_local.")" | sort start | table capture label]]></query>
      </search>
      <fieldForLabel>label</fieldForLabel>
      <fieldForValue>capture</fieldForValue>
      <default>__all</default>
    </input>
    <input type="dropdown" token="dev" searchWhenChanged="true">
      <label>Device</label>
      <choice value="__all">All devices</choice>
      <search>
        <query><![CDATA[| inputlookup iot_devices | where role!="controller" | sort role device | table device]]></query>
      </search>
      <fieldForLabel>device</fieldForLabel>
      <fieldForValue>device</fieldForValue>
      <default>__all</default>
    </input>
    <input type="dropdown" token="min_sev" searchWhenChanged="true">
      <label>Minimum severity for detection panels</label>
      <choice value="1">Info and above (everything)</choice>
      <choice value="2">Low and above</choice>
      <choice value="3">Medium and above</choice>
      <choice value="4">High and above</choice>
      <choice value="5">Critical only</choice>
      <default>2</default>
    </input>
    <input type="radio" token="tests" searchWhenChanged="true">
      <label>Test host (simulated attacks)</label>
      <choice value="yes">Include</choice>
      <choice value="no">Real devices only</choice>
      <default>yes</default>
    </input>
  </fieldset>'''
    return (f'<form version="1.1" theme="dark">\n  <label>IoT Segmentation: Smart-Home Network Overview</label>\n'
            f'  <description>Device behaviour, detections and firewall evidence for the segmented smart-home network. '
            f'Counters and charts follow all filters; the severity filter applies to the detection panels only.</description>\n'
            f'{base_det}\n{fieldset}\n' + '\n'.join(rows) + '\n</form>\n')


NAV = '''<nav search_view="search" color="#3c444d">
  <view name="iot_overview" default="true" />
  <view name="search" />
  <view name="dashboards" />
</nav>
'''
