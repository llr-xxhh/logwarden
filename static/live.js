/* LogWarden browser/API integration. No demonstration records are created here. */
(function(){
  if(location.protocol==='file:')return;
  var BOOT=null,TASK_DATA=null,TASK_ID=null,ALERT_CACHE=null;
  var loadSerial=0,taskSerial=0,alertSerial=0,previewSerial=0,taskBound=false;
  var SRC_SHOW_EMPTY=false,NT_SRC={};
  var legacy={dash:renderDash,stats:renderStats,arch:renderArch};
  var prototypes={};
  SOURCES.forEach(function(s){if(!prototypes[s.kind])prototypes[s.kind]=s});
  prototypes.text={cols:COLS_SYSLOG,detect:detectSyslog,ph:'搜索消息 / 主机 / 进程，支持正则 /pattern/',dims:[{k:'proc',lb:'进程'},{k:'level',lb:'级别'},{k:'host',lb:'主机'}]};
  function detectFirewall(l){
    var f=[],msg=l.msg||'';
    if(l.action==='deny')addFlag(f,'拒绝','md',[mkText('action',l.action)]);
    if(l.action==='accept'&&[22,23,135,139,445,3389,5900].indexOf(l.dstport)>=0)addFlag(f,'管理端口放行','hi',[mkText('dstport',l.dstport)]);
    if(/login|authentication|认证|登录/i.test(msg)&&/fail|deny|失败|拒绝/i.test(msg))addFlag(f,'管理员登录失败','md',[mkRe('msg',/login|authentication|认证|登录|fail|deny|失败|拒绝/gi)]);
    if(/policy|rule|config|策略|配置/i.test(msg)&&/add|delete|modify|change|新增|删除|修改/i.test(msg))addFlag(f,'策略变更','hi',[mkRe('msg',/policy|rule|config|策略|配置|add|delete|modify|change|新增|删除|修改/gi)]);
    return f;
  }
  prototypes.firewall={
    cols:[{k:'ts',lb:'时间',w:148,mono:1},{k:'host',lb:'设备',w:110,mono:1},{k:'vendor',lb:'厂商',w:90},{k:'action',lb:'动作',w:70},{k:'protocol',lb:'协议',w:66},{k:'srcip',lb:'来源 IP',w:120,mono:1},{k:'srcport',lb:'源端口',w:72},{k:'dstip',lb:'目的 IP',w:120,mono:1},{k:'dstport',lb:'目的端口',w:76},{k:'rule',lb:'命中策略',w:130,mono:1},{k:'msg',lb:'原始消息',w:0,flex:1,mono:1},{k:'flags',lb:'标记',w:140}],
    detect:detectFirewall,ph:'搜索 IP / 端口 / 策略 / 原始消息，支持正则 /pattern/',
    dims:[{k:'srcip',lb:'来源 IP',t:'ip'},{k:'action',lb:'动作'},{k:'dstip',lb:'目的 IP'},{k:'dstport',lb:'目的端口'},{k:'protocol',lb:'协议'},{k:'rule',lb:'命中策略'},{k:'host',lb:'设备'}]
  };
  SRC_LB.firewall='防火墙';

  function api(path,options){
    options=options||{};
    var headers=options.headers||{};
    if(options.json!==undefined){
      options.body=JSON.stringify(options.json);headers['Content-Type']='application/json';delete options.json;
    }
    options.headers=headers;
    return fetch('/api'+path,options).then(function(res){
      return res.text().then(function(text){
        var data={};try{data=text?JSON.parse(text):{}}catch(e){data={detail:text}}
        if(!res.ok)throw new Error(data.detail||('HTTP '+res.status));
        return data;
      });
    });
  }
  function copyObj(o){var n={};for(var k in o)if(Object.prototype.hasOwnProperty.call(o,k))n[k]=o[k];return n}
  function sevName(s){return s==='high'?'高':s==='medium'?'中':'低'}
  function sevValue(s){return s==='高'?'high':s==='中'?'medium':'low'}
  function groupName(src){if(src.distro)return src.distro;return src.group==='web'?'Web':src.group==='linux'?'Linux':src.group==='windows'?'Windows':src.group==='security'?'安全':'其他'}
  function appliesFor(scope){
    if(scope==='all'||!scope)return [];
    if(scope==='syslog')return ['auth','syslog'];
    return Object.prototype.toString.call(scope)==='[object Array]'?scope:[scope];
  }
  function valueText(v){return v==null?'':String(v)}
  function condition(actual,expr){
    var text=valueText(actual),ok=true;
    Object.keys(expr||{}).forEach(function(op){
      if(!ok)return;
      var expected=expr[op],left,right;
      if(op==='eq')ok=valueText(actual)===valueText(expected);
      else if(op==='ne')ok=valueText(actual)!==valueText(expected);
      else if(['gt','gte','lt','lte'].indexOf(op)>=0){
        left=Number(actual);right=Number(expected);if(isNaN(left)||isNaN(right))ok=false;
        else if(op==='gt')ok=left>right;else if(op==='gte')ok=left>=right;else if(op==='lt')ok=left<right;else ok=left<=right;
      }else if(op==='in')ok=expected.map(valueText).indexOf(text)>=0;
      else if(op==='not_in')ok=expected.map(valueText).indexOf(text)<0;
      else if(op==='contains')ok=text.indexOf(String(expected))>=0;
      else if(op==='icontains')ok=text.toLowerCase().indexOf(String(expected).toLowerCase())>=0;
      else if(op==='contains_any')ok=expected.some(function(x){return text.indexOf(String(x))>=0});
      else if(op==='icontains_any')ok=expected.some(function(x){return text.toLowerCase().indexOf(String(x).toLowerCase())>=0});
      else if(op==='starts_with')ok=text.indexOf(String(expected))===0;
      else if(op==='ends_with')ok=text.slice(-String(expected).length)===String(expected);
      else if(op==='regex'||op==='iregex'||op==='not_regex'){
        var found=false;try{found=new RegExp(expected,op==='iregex'?'i':'').test(text)}catch(e){}
        ok=op==='not_regex'?!found:found;
      }else if(op==='len_lt')ok=text.length<Number(expected);
      else if(op==='len_gt')ok=text.length>Number(expected);
      else if(op==='len_eq')ok=text.length===Number(expected);
      else if(op==='exists')ok=expected?actual!=null&&actual!=='':actual==null||actual==='';
      else if(op==='not_exists')ok=expected?actual==null||actual==='':actual!=null&&actual!=='';
    });
    return ok;
  }
  function matchTest(match){
    return function(row){
      function walk(m){
        if(!m)return true;
        if(m.agg)return false;
        return Object.keys(m).every(function(field){
          if(field==='any')return m.any.some(walk);
          if(field==='not')return !walk(m.not);
          return condition(row[field],m[field]);
        });
      }
      return walk(match);
    };
  }
  function ruleMatchMarks(raw,row){
    var marks=[];
    function collect(match){
      if(!match||typeof match!=='object')return;
      Object.keys(match).forEach(function(field){
        var expr=match[field];
        if(field==='any'){expr.forEach(function(sub){if(matchTest(sub)(row))collect(sub)});return}
        if(field==='not'||field==='agg')return;
        if(!condition(row[field],expr))return;
        Object.keys(expr).forEach(function(op){
          var expected=expr[op];
          if(op==='regex'||op==='iregex'){
            try{marks.push(mkRe(field,new RegExp(expected,op==='iregex'?'gi':'g')))}catch(e){}
          }else if(op==='contains'||op==='icontains'||op==='starts_with'||op==='ends_with')marks.push(mkText(field,expected));
          else if(op==='contains_any'||op==='icontains_any')expected.forEach(function(v){if(row[field]!=null&&String(row[field]).toLowerCase().indexOf(String(v).toLowerCase())>=0)marks.push(mkText(field,v))});
          else if(op==='eq'||op==='in'||(op==='exists'&&expected))marks.push(mkText(field,row[field]));
        });
      });
    }
    if(matchTest(raw.match||{})(row))collect(raw.match||{});
    return marks;
  }
  function markServerRows(rows,fallback){
    rows.forEach(function(l){
      if(!Array.isArray(l.ruleHits)){l.flags=fallback(l);l.crit=l.flags.some(function(f){return f[1]==='hi'});l.marks=collectMarks(l,l.flags);return}
      l.flags=[];l.marks=[];
      l.ruleHits.forEach(function(hit){
        var r=workRules().filter(function(x){return x.id===hit.id})[0];
        addFlag(l.flags,hit.name,hit.severity==='high'?'hi':hit.severity==='medium'?'md':'lo',r?ruleMatchMarks(r._raw,l):[]);
      });
      l.crit=l.flags.some(function(f){return f[1]==='hi'});l.marks=collectMarks(l,l.flags);
    });
    return rows;
  }
  function convertRule(r){
    var field='any',re='',match=r.match||{};
    var keys=Object.keys(match);if(keys.length===1&&keys[0]!=='any'&&keys[0]!=='not'&&keys[0]!=='agg'){
      field=keys[0];var expr=match[field]||{};re=expr.iregex||expr.regex||'';
    }
    return {id:r.id,name:r.name,cat:r.category_name||r.category||'未分类',sev:sevName(r.severity),prio:r.priority==null?100:r.priority,
      applies:appliesFor(r.scope),why:r.explain||'',falsePositive:r.false_positive||'',field:field,re:re,
      body:JSON.stringify(match,null,2),enabled:r.enabled!==false,builtin:!!r.builtin,kind:r.kind,
      attack:r.attack||[],triage:r.triage||'',references:r.references||[],
      test:matchTest(match),_raw:r};
  }
  function loadRules(){
    // 规则文件坏掉时后端会跳过该文件，这里把失败清单取回来显示，避免整批规则静默消失
    return Promise.all([
      api('/rules'),
      api('/rules/errors').catch(function(){return []})
    ]).then(function(res){
      var items=res[0];window.RULE_ERRORS=res[1]||[];
      RULES=items.map(convertRule);refreshRuleCats();renderRules();
      syncBaselineFromRule();
      if(window.RULE_ERRORS.length)toast(window.RULE_ERRORS.length+' 个规则文件加载失败，规则管理页可查看原因');
      return RULES;
    });
  }
  function refreshAfterRuleChange(){return loadRules().then(function(){if(CURRENT)return loadCurrentRows();renderAlerts()})}
  workRules=function(){return RULES.slice().sort(function(a,b){return (b.prio||0)-(a.prio||0)})};
  saveRuleOvr=function(){};
  setRuleEnabled=function(id,on){
    var r=workRules().filter(function(x){return x.id===id})[0];if(!r)return;
    var raw=copyObj(r._raw);raw.enabled=on;
    api('/rules/'+encodeURIComponent(id),{method:'PUT',json:raw}).then(refreshAfterRuleChange).catch(function(e){toast(e.message)});
  };
  delRules=function(ids){
    var chain=Promise.resolve();ids.forEach(function(id){chain=chain.then(function(){return api('/rules/'+encodeURIComponent(id),{method:'DELETE'})})});
    chain.then(refreshAfterRuleChange).then(function(){RSTATE.sel={};renderRules()}).catch(function(e){toast(e.message)});
  };
  saveRuleModal=function(){
    var name=document.getElementById('rmName').value.trim(),err=document.getElementById('rmErr');
    var cat=document.getElementById('rmCat').value.trim()||'未分类';
    var why=document.getElementById('rmWhy').value.trim();
    var apps=Object.keys(RSTATE.applySel).filter(function(k){return RSTATE.applySel[k]});
    if(!name){err.textContent='规则名称不能为空';return}
    var editing=RSTATE.editing,r=editing?workRules().filter(function(x){return x.id===editing})[0]:null;
    var raw=r?copyObj(r._raw):{kind:'row',match:{}};
    raw.name=name;raw.category=cat;raw.category_name=cat;raw.severity=sevValue(document.getElementById('rmSev').value);
    var prio=parseInt(document.getElementById('rmPrio').value,10);raw.priority=isNaN(prio)?50:prio;
    raw.explain=why;raw.false_positive=(r&&r._raw.false_positive)||'请结合业务上下文确认';raw.enabled=document.getElementById('rmOn').checked;
    if(!apps.length){err.textContent='请至少选择一种适用日志类型';return}
    raw.scope=apps.length===1?apps[0]:apps;
    if(!r||!r.builtin){
      var re=document.getElementById('rmRe').value.trim(),field=document.getElementById('rmField').value;
      if(!re){err.textContent='匹配正则为空';return}
      try{new RegExp(re)}catch(e){err.textContent='正则语法错误：'+e.message;return}
      raw.match={};raw.match[field==='any'?'raw':field]={iregex:re};raw.kind='row';
    }
    api(editing?'/rules/'+encodeURIComponent(editing):'/rules',{method:editing?'PUT':'POST',json:raw}).then(refreshAfterRuleChange).then(function(){closeRuleModal();toast('规则已保存')}).catch(function(e){err.textContent=e.message});
  };

  function srcLabel(src){
    // CentOS 认证日志（secure） → secure：发行版靠分组标签区分，按钮上只留文件名
    var m=/[（(]([^）)]+)[）)]/.exec(src.name||'');
    if(src.distro&&m)return m[1];
    if(src.distro)return String(src.name||'').replace(src.distro,'').trim();
    return String(src.name||src.id||'');
  }
  function sourceView(src){
    var proto=prototypes[src.kind]||prototypes.text;
    return {id:src.id,short:srcLabel(src),name:src.name,file:(src.paths||[]).join(' · '),kind:src.kind,tag:groupName(src),
      distro:src.distro,paths:src.paths||[],level:src.level,
      rows:[],count:src.count||0,loaded:false,cols:proto.cols,detect:proto.detect,ph:proto.ph,dims:proto.dims,format:src.format};
  }
  function applyTask(data,preferred){
    ++loadSerial;++alertSerial;
    TASK_DATA=data;TASK_ID=data.id;localStorage.setItem('logview.current.task',TASK_ID);
    TASK={name:data.name,arch:data.arch,components:(data.evidence||[]).map(function(c){return {name:c.name,note:c.desc,basis:c.basis||'required',logs:c.logs.map(function(l){return {lb:l.name,fmt:l.format,srcId:l.id,level:l.level||'',state:l.state==='off'?'off':null,note:l.state==='off'?'默认未开启':'',paths:l.paths||[]}})}})};
    SOURCES=(data.sources||[]).map(sourceView);
    var wanted=preferred||localStorage.getItem('logview.current.source.'+TASK_ID);
    CURRENT=null;
    SOURCES.forEach(function(s){if(s.id===wanted)CURRENT=s});
    if(!CURRENT)SOURCES.forEach(function(s){if(!CURRENT&&s.count)CURRENT=s});
    if(!CURRENT&&SOURCES.length)CURRENT=SOURCES[0];
    ALERT_CACHE=null;NEED_ST={};renderTaskList();renderImportForms();renderImportNeed();renderFormatBox();
    if(CURRENT){LOGS=[];COLS=CURRENT.cols;loadCurrentRows()}else{
      LOGS=[];COLS=COLS_WEB;COLSTATE=initColState(COLS,'empty',[]);renderSrcBar();renderTable();renderArch();
      document.getElementById('alertBox').innerHTML='<div class="alerts-empty">当前任务没有日志源</div>';document.getElementById('navAlert').textContent='0';renderDash();
      showPage('import');toast('该任务还没有日志源，请导入或重新选择组件');
    }
  }
  function loadTask(id,preferred){
    var serial=++taskSerial;++loadSerial;++alertSerial;
    return api('/tasks/'+encodeURIComponent(id)).then(function(data){
      if(serial!==taskSerial)return null;
      applyTask(data,preferred);return data;
    }).catch(function(e){if(serial===taskSerial)toast(e.message);throw e});
  }
  // 模板补出来的列拼到静态列后面。固定列保留宽度和格式化，动态列给默认宽度并标记 dyn，
  // 默认收起，用户在「字段」里勾出来才显示。
  function mergeCols(base,schema,source){
    if(!schema||!schema.length){source.dynCols=0;return base}
    if(!source._baseDims)source._baseDims=(source.dims||[]).slice();
    var have={};base.forEach(function(c){have[c.k]=1});
    var extra=[];
    schema.forEach(function(c){
      if(have[c.name])return;
      extra.push({k:c.name,lb:FIELD_LB[c.name]||c.name,w:130,mono:1,dyn:1,num:(c.type==='REAL'||c.type==='INTEGER')});
    });
    source.dynCols=extra.length;
    // 模板带出来的列同时进统计维度，否则"能存不能分析"还是半截
    var seen={};source._baseDims.forEach(function(d){seen[d.k]=1});
    source.dims=source._baseDims.concat(extra.filter(function(c){return !seen[c.k]}).map(function(c){return {k:c.k,lb:c.lb}}));
    return extra.length?base.concat(extra):base;
  }

  function loadCurrentRows(){
    if(!CURRENT)return Promise.resolve();
    var source=CURRENT,serial=++loadSerial,taskId=TASK_ID;
    ++alertSerial;ALERT_CACHE=null;document.getElementById('navAlert').textContent='0';
    source.rows=[];source.loaded=false;LOGS=source.rows;
    renderSrcBar();document.getElementById('rows').innerHTML='<tr><td style="padding:36px;text-align:center;color:var(--faint)">正在读取 '+esc(source.name)+' …</td></tr>';
    var PAGE=5000,total=0,schema=null;
    function stale(){return serial!==loadSerial||taskId!==TASK_ID||!CURRENT||CURRENT.id!==source.id}
    function bodyFor(cursor,first){
      var body={source_id:source.id,size:PAGE,sort:{k:'id',dir:1}};
      if(cursor!=null){body.cursor=cursor}else{body.page=1}
      // 续页不需要 total（每页算一次 COUNT(*) 等于把整表数 55 遍），
      // 也不需要 raw 原文（占响应 70%+）；首屏那份保留，模板样本等功能要用
      if(!first){body.count=false;body.omit=['raw']}
      return body;
    }
    function finish(){
      source.rows.sort(function(a,b){if(a.ts==null)return 1;if(b.ts==null)return -1;return a.ts-b.ts||a.id-b.id});
      markServerRows(source.rows,source.detect);source.loaded=true;
      LOGS=source.rows;COLS=mergeCols(source.cols,schema,source);COLSTATE=initColState(COLS,source.id,defHiddenFor(source.id,source.kind,COLS));
      // 换源后原维度可能已不存在（比如从 nginx 切到 syslog），退回默认，否则排行全是 "-"
      if(!colDef(topDim))topDim='ip';
      state.page=1;state.q='';state.status='';state.fk={};state.colf={};state.sort={k:'',dir:1};state.focusId=null;
      var qi=document.getElementById('q');if(qi)qi.value='';
      renderSrcBar();renderFilterBar();renderAll();renderFormatBox();
      var current=document.querySelector('.page.on');showPage(current?current.id.replace('p-',''):'dash');
    }
    function fetchPage(cursor,first){
      return api('/tasks/'+encodeURIComponent(taskId)+'/query',{method:'POST',json:bodyFor(cursor,first)});
    }
    // 游标顺序加载：每页恒定 ~9ms（OFFSET 深分页递增到 200ms+）。
    // 不再并发——游标是链式的，且单页 5000 行时总往返数已足够少。
    return fetchPage(null,true).then(function page_loop(page){
      if(stale())return null;
      if(page.schema)schema=page.schema;
      if(page.total!=null)total=page.total;
      if(page.rows&&page.rows.length)source.rows=source.rows.concat(page.rows);
      var loaded=source.rows.length;
      var cell=document.getElementById('rows');
      if(cell&&loaded<total)cell.innerHTML='<tr><td style="padding:36px;text-align:center;color:var(--faint)">正在读取 '+esc(source.name)+' … '+loaded+' / '+total+'</td></tr>';
      if(page.next_cursor!=null&&!stale()){
        return fetchPage(page.next_cursor,false).then(page_loop);
      }
      if(!stale())finish();
      return null;
    }).catch(function(e){
      if(serial!==loadSerial||taskId!==TASK_ID)return;
      LOGS=[];source.rows=[];source.loaded=false;renderSrcBar();renderDash();
      document.getElementById('alertBox').innerHTML='<div class="alerts-empty">日志读取失败，未显示其它来源的旧结果</div>';
      toast('读取日志失败：'+e.message);document.getElementById('rows').innerHTML='<tr><td style="padding:36px;text-align:center;color:var(--red)">'+esc(e.message)+'</td></tr>';
    });
  }
  switchSource=function(id){
    var next=null;SOURCES.forEach(function(s){if(s.id===id)next=s});
    if(!next||next.id===(CURRENT&&CURRENT.id))return;
    // 只保留当前源的行；否则每切一个源就多留一份全量数组，几十万行时浏览器内存会一直涨
    SOURCES.forEach(function(s){if(s.id!==id){s.rows=[];s.loaded=false}});
    CURRENT=next;localStorage.setItem('logview.current.source.'+TASK_ID,id);ALERT_CACHE=null;loadCurrentRows();
  };
  taskMeta=function(){
    var stats=TASK_DATA?TASK_DATA.stats:{total:0,sources:0,first:null,last:null};
    return {total:stats.total||0,sources:stats.sources||0,first:stats.first,last:stats.last};
  };
  srcState=function(log){
    if(log.state)return {st:log.state,note:log.note||'',n:0};
    var s=null;SOURCES.forEach(function(x){if(x.id===log.srcId)s=x});
    if(!s)return {st:'miss',note:'待导入',n:0};
    return s.count?{st:'ok',note:s.short+' · '+s.count+' 条',n:s.count,srcId:s.id}:{st:'miss',note:'已配置，暂无数据',n:0,srcId:s.id};
  };
  renderArch=function(){
    legacy.arch();var name=document.getElementById('taskCurName');if(name&&TASK_DATA)name.textContent=TASK_DATA.name;
  };
  /* 日志清单：按「必要项 / 推荐项 / 可选项」三级展示，级别来自 catalog 的 level 字段。
     用户当初勾源只是决定「收哪些」，级别决定「缺了算不算问题」——两件事不能混。 */
  var LEVELS=[{k:'required',lb:'必要项',cls:'req',rank:0},{k:'recommended',lb:'推荐项',cls:'rec',rank:1},{k:'optional',lb:'可选项',cls:'opt',rank:2}];
  function levelOf(log){
    var i;for(i=0;i<LEVELS.length;i++){if(LEVELS[i].k===log.level)return LEVELS[i]}
    return LEVELS[1];
  }
  function renderImportNeed(){
    var box=document.getElementById('importNeed'),wrap=document.getElementById('importNeedBox'),sum=document.getElementById('importNeedSum');
    if(!box||!wrap)return;
    var groups={required:[],recommended:[],optional:[]};
    (TASK.components||[]).forEach(function(c){
      (c.logs||[]).forEach(function(l){
        var lv=levelOf(l);
        groups[lv.k].push({c:c.name,l:l,lv:lv,st:srcState(l).st});
      });
    });
    var total=groups.required.length+groups.recommended.length+groups.optional.length;
    if(!total){wrap.style.display='none';return}
    wrap.style.display='';
    var parts=[];
    LEVELS.forEach(function(lv){
      var arr=groups[lv.k];if(!arr.length)return;
      var got=0;arr.forEach(function(x){if(x.st==='ok')got++});
      parts.push(lv.lb+' '+got+'/'+arr.length);
    });
    if(sum)sum.textContent=parts.join(' · ');
    var order={miss:0,off:1,ok:2},html='';
    LEVELS.forEach(function(lv){
      var arr=groups[lv.k];
      if(!arr.length)return;
      arr=arr.slice().sort(function(a,b){return (order[a.st]-order[b.st])||((a.c<b.c)?-1:(a.c>b.c?1:0))});
      html+='<div class="needgrp">'+lv.lb+' · '+arr.length+' 项</div>';
      html+=arr.map(function(x){
        var note=x.st==='ok'?'已导入 '+(srcState(x.l).n||0)+' 条':(x.st==='off'?'默认未开启，可先导入分析':'待导入');
        var sid=esc(x.l.srcId);
        var st=NEED_ST[sid];
        var ctl=x.st==='ok'
          ? '<span class="needok">已收</span>'
          : '<div class="pickbox"><div class="pickin">'
            +'<div class="ndrop'+(st&&st.busy?' hot':'')+'" data-ndrop="'+sid+'">'+(st&&st.busy?esc(st.text):'<span class="nd1">拖入导入日志</span><span class="nd2">拖到此行直接导入</span>')+'</div>'
            +'<button class="pbtn" data-need-pick="file" data-need="'+sid+'" data-need-name="'+esc(x.l.lb)+'">选择文件导入</button>'
            +'</div></div>';
        var ps=(x.l.paths||[]).filter(function(p){return p&&String(p).trim()});
        var pth=ps.length
          ? '<div class="n3" data-copy="'+esc(ps.join('\n'))+'"><b>点击复制路径：</b>'+esc(ps[0])+(ps.length>1?'  +'+(ps.length-1):'')+'</div>'
          : '<div class="n3 none">未提供默认路径</div>';
        return '<div class="need"><div class="need-main"><span class="ntlv '+x.lv.cls+'">'+x.lv.lb+'</span><div class="nw"><div class="n1">'+esc(x.l.lb)+'</div><div class="n2">'+esc(x.c)+' · 解析格式 '+esc(x.l.fmt)+' · '+esc(note)+'</div></div>'+ctl+'</div>'+pth+'</div>';
      }).join('');
    });
    box.innerHTML=html;
    box.onclick=function(e){
      var cp=e.target.closest?e.target.closest('[data-copy]'):null;
      if(cp){
        var ok=copyText(cp.getAttribute('data-copy'),true);
        if(ok){
          // 不弹框，靠行内文字给反馈：前缀闪一下「已复制」
          var b=cp.querySelector('b');
          if(b&&!b.getAttribute('data-flash')){
            b.setAttribute('data-flash','1');
            var old=b.textContent;b.textContent='已复制 ✓';
            setTimeout(function(){b.textContent=old;b.removeAttribute('data-flash')},1000);
          }
        }
        return;
      }
      var b=e.target.closest?e.target.closest('[data-need-pick]'):null;if(!b)return;
      if(!requireTask())return;
      NEED_PICK_SRC=b.getAttribute('data-need');
      document.getElementById('fileInput').click();
    };
    box.ondragover=function(e){
      var z=e.target.closest?e.target.closest('[data-ndrop]'):null;
      if(z){e.preventDefault();z.classList.add('hot')}
    };
    box.ondragleave=function(e){
      var z=e.target.closest?e.target.closest('[data-ndrop]'):null;
      if(z)z.classList.remove('hot');
    };
    box.ondrop=function(e){
      var z=e.target.closest?e.target.closest('[data-ndrop]'):null;
      if(!z)return;
      e.preventDefault();e.stopPropagation();
      z.classList.remove('hot');
      var sid=z.getAttribute('data-ndrop');
      var items=e.dataTransfer.items;
      if(items&&items.length&&items[0].webkitGetAsEntry)collectDirEntries(items,function(out,scanned){importToSource(sid,out.length?out:[])});
      else if(e.dataTransfer.files.length)importToSource(sid,Array.prototype.map.call(e.dataTransfer.files,function(f){return {file:f,path:f.name}}));
    };
  }
  /* 清单行内导入：归属已被行固定，不用确认清单，直接批量入库并在行内显示进度 */
  var NEED_ST={},NEED_PICK_SRC=null;
  function importToSource(sid,list){
    var files=list.filter(function(x){return x&&x.file&&isLogish(x.path||x.file.name)&&x.file.size<=MAX_FILE});
    if(!files.length){toast('没有可导入的日志文件');return}
    var taskId=TASK_ID,enc=(document.getElementById('importEncoding')||{value:'utf-8'}).value;
    var idx=0,okRows=0,okFiles=0,failFiles=0;
    NEED_ST[sid]={busy:true,text:'导入中 0/'+files.length};
    function paint(){renderImportNeed()}
    function next(){
      if(idx>=files.length||taskId!==TASK_ID){
        var summary='入库 '+okFiles+' 个文件 '+okRows+' 行'+(failFiles?'，失败 '+failFiles:'');
        NEED_ST[sid]={busy:false,text:summary};
        paint();
        toast('「'+(sourceNameById(sid)||sid)+'」'+summary);
        if(taskId===TASK_ID)loadTask(taskId,sid);
        return;
      }
      NEED_ST[sid]={busy:true,text:'导入中 '+(idx+1)+'/'+files.length+'：'+files[idx].path.split(/[\\/]/).pop()};
      paint();
      var fd=new FormData();fd.append('file',files[idx].file);fd.append('source_id',sid);fd.append('fmt','');fd.append('encoding',enc);
      api('/tasks/'+encodeURIComponent(taskId)+'/imports',{method:'POST',body:fd}).then(function(result){
        okRows+=result.rows;okFiles++;
      }).catch(function(e){failFiles++;}).then(function(){idx++;next()});
    }
    next();
  }
  renderSrcBar=function(){
    var box=document.getElementById('srcList');if(!box)return;
    // 默认只列有数据的源；当前选中的源本身为空时强制展开，否则看不到自己在看哪一条
    var showEmpty=SRC_SHOW_EMPTY||(CURRENT&&!CURRENT.count);
    var groups=[];SOURCES.forEach(function(s){if(groups.indexOf(s.tag)<0)groups.push(s.tag)});
    var hidden=0;
    var html=groups.map(function(g){
      var all=SOURCES.filter(function(s){return s.tag===g});
      var vis=showEmpty?all:all.filter(function(s){return s.count>0});
      hidden+=all.length-vis.length;
      if(!vis.length)return '';
      return '<span class="grp">'+esc(g)+'</span>'+vis.map(function(s){
        return '<div class="src'+(CURRENT&&s.id===CURRENT.id?' on':'')+(s.count?'':' empty')+'" data-src="'+esc(s.id)+'" title="'+esc(s.name)+' · '+esc(s.file)+' · '+s.count+' 条"><span class="n">'+esc(s.short)+'</span><span class="c">'+s.count+'</span></div>';
      }).join('');
    }).join('');
    var emptyN=0;SOURCES.forEach(function(s){if(!(s.count>0))emptyN++});
    if(showEmpty&&emptyN)html+='<div class="src more" data-more="1" title="收起还没有数据的日志源">收起 '+emptyN+' 个空源</div>';
    else if(hidden)html+='<div class="src more" data-more="1" title="展开还没有数据的日志源，点开可先进去导入">+ '+hidden+' 待导入</div>';
    box.innerHTML=html||'<span style="color:#d1ebe8;font-size:12px">当前任务没有可选日志源，请重新建任务</span>';
    box.onclick=function(e){
      var el=e.target.closest?e.target.closest('.src'):null;if(!el)return;
      if(el.getAttribute('data-more')){
        SRC_SHOW_EMPTY=!showEmpty;
        // 当前源本身是空的（新任务刚建），收起后自动跳到第一个有数据的源，避免台面全空
        if(!SRC_SHOW_EMPTY&&CURRENT&&!CURRENT.count){
          var first=null;SOURCES.forEach(function(s){if(!first&&s.count>0)first=s});
          if(first){switchSource(first.id);return}
        }
        renderSrcBar();return;
      }
      switchSource(el.getAttribute('data-src'));
    };
  };
  function renderTaskList(){
    var box=document.getElementById('taskList');if(!box)return;
    var tasks=BOOT?BOOT.tasks:[];if(TASK_DATA){var found=false;tasks.forEach(function(t,i){if(t.id===TASK_DATA.id){tasks[i]=TASK_DATA;found=true}});if(!found)tasks.unshift(TASK_DATA)}
    box.innerHTML='<div class="sec">任务</div>'+tasks.map(function(t){
      var current=t.id===TASK_ID,st=t.stats||{};
      return '<div class="task'+(current?' on':'')+'" data-task="'+esc(t.id)+'" '+(current?'id="taskCurrent"':'')+'><div class="t1" '+(current?'id="taskCurName"':'')+'>'+esc(t.name)+'</div><div class="t2" '+(current?'id="taskCurMeta"':'')+'>'+(st.total||0).toLocaleString()+' 条 · '+(st.sources||0)+' 份日志</div><button class="tdel" data-del-task="'+esc(t.id)+'" title="删除任务「'+esc(t.name)+'」">×</button></div>';
    }).join('')||'<div class="sec">任务</div><div style="padding:10px;color:#7fc3bc;font-size:12px">还没有排查任务</div>';
    box.onclick=function(e){
      var del=e.target.closest?e.target.closest('[data-del-task]'):null;
      if(del){e.stopPropagation();deleteTaskFlow(del.getAttribute('data-del-task'));return}
      var el=e.target.closest?e.target.closest('[data-task]'):null;
      if(el&&el.getAttribute('data-task')!==TASK_ID)loadTask(el.getAttribute('data-task'));
    };
  }
  /* ===== 删除：任务（过时）与导入批次（导错） =====
     两种删除都不可逆，统一走确认弹窗，不做 browser confirm。 */
  function openDialog(cfg){
    var modal=document.getElementById('delModal');if(!modal)return;
    document.getElementById('dmTitle').textContent=cfg.title||'确认删除';
    document.getElementById('dmSub').textContent=cfg.sub||'';
    document.getElementById('dmBody').innerHTML=cfg.body||'';
    var foot=document.getElementById('dmFoot'),buttons=cfg.buttons||[];
    foot.innerHTML=buttons.map(function(b,i){return '<button class="'+(b.cls||'')+'" data-dmb="'+i+'">'+esc(b.label)+'</button>'}).join('');
    foot.onclick=function(e){
      var btn=e.target.closest?e.target.closest('[data-dmb]'):null;if(!btn||btn.disabled)return;
      var item=buttons[Number(btn.getAttribute('data-dmb'))];
      if(!item||!item.act){closeDialog();return}
      var pending=item.act();
      if(pending&&pending.then){btn.disabled=true;pending.then(closeDialog).catch(function(err){btn.disabled=false;toast(err.message)})}
      else closeDialog();
    };
    modal.classList.add('on');
  }
  function closeDialog(){var m=document.getElementById('delModal');if(m)m.classList.remove('on')}
  document.getElementById('delModal').onclick=function(e){if(e.target===this)closeDialog()};
  document.addEventListener('keydown',function(e){
    if(e.key!=='Escape')return;
    closeDialog();var t=document.getElementById('taskModal');if(t)t.classList.remove('on');
  });
  function sourceNameById(sid){
    var name=sid;SOURCES.forEach(function(s){if(s.id===sid)name=s.name});
    return name;
  }
  function deleteTaskFlow(taskId){
    if(!taskId){toast('还没有选中任务');return}
    var task=null;(BOOT.tasks||[]).forEach(function(t){if(t.id===taskId)task=t});
    var st=(task&&task.stats)||{},isCurrent=taskId===TASK_ID;
    openDialog({
      title:'删除任务',sub:isCurrent?'当前任务':'',
      body:'<div class="dlg-name">'+esc(task?task.name:taskId)+'</div>'
        +'<div class="dlg-meta">'+(st.total||0).toLocaleString()+' 条日志 · '+(st.sources||0)+' 份日志源'+(task&&task.created_at?' · 创建于 '+esc(fmtTime(task.created_at)):'')+'</div>'
        +'<div class="dlg-note"><b>仅移出列表</b>：左侧不再显示，data/ 下的数据文件保留，可手工恢复。<br><b>永久删除</b>：连同 task_*.db 一起删除，<span class="warn">该任务的全部日志不可恢复</span>。</div>',
      buttons:[
        {label:'取消'},
        {label:'仅移出列表',act:function(){return removeTask(taskId,false)}},
        {label:'永久删除',cls:'danger',act:function(){return removeTask(taskId,true)}}
      ]
    });
  }
  function removeTask(taskId,permanent){
    var url='/tasks/'+encodeURIComponent(taskId)+(permanent?'?permanent=true':'');
    return api(url,{method:'DELETE'}).then(function(){
      BOOT.tasks=(BOOT.tasks||[]).filter(function(t){return t.id!==taskId});
      if(taskId!==TASK_ID){renderTaskList();toast(permanent?'任务已永久删除':'任务已移出列表');return}
      var next=BOOT.tasks[0];
      if(!next){location.reload();return}
      return loadTask(next.id).then(function(){toast(permanent?'任务已永久删除':'任务已移出列表，数据文件保留')});
    });
  }
  function deleteImportFlow(importId){
    if(!TASK_DATA)return;
    var imp=null;(TASK_DATA.imports||[]).forEach(function(i){if(i.id===importId)imp=i});
    if(!imp)return;
    var badge=importBadge(imp);
    openDialog({
      title:'删除这次导入',sub:badge.text,
      body:'<div class="dlg-name">'+esc(imp.filename)+'</div>'
        +'<div class="dlg-meta">'+esc(sourceNameById(imp.source_id))+' · '+imp.rows+' 行入库 · '+imp.failed+' 行失败 · '+esc(fmtTime(imp.created_at))+'</div>'
        +'<div class="dlg-note">只回滚这一批：删除它写入的 <b>'+imp.rows+'</b> 行，任务本身和该日志源的其它导入不受影响。<br>用于选错日志源、选错解析格式或传错文件的场景，删完重新导一次即可。</div>',
      buttons:[{label:'取消'},{label:'删除这批日志',cls:'danger',act:function(){
        return api('/tasks/'+encodeURIComponent(TASK_ID)+'/imports/'+encodeURIComponent(importId),{method:'DELETE'}).then(function(result){
          var keep=CURRENT&&CURRENT.id;
          return loadTask(TASK_ID,keep).then(function(){
            toast('已删除 '+result.deleted_rows+' 行'+(result.dropped_tables&&result.dropped_tables.length?'，空表已回收磁盘':''));
          });
        });
      }}]
    });
  }
  function importBadge(imp){
    if(imp.status==='done'&&!imp.failed)return {text:'完成',cls:'ok'};
    if(imp.status==='done'&&imp.failed)return {text:'部分失败',cls:'md'};
    if(imp.status==='running')return {text:'未完成',cls:'md'};
    if(imp.status==='failed')return {text:'全部失败',cls:'hi'};
    return {text:imp.status||'未知',cls:'hi'};
  }
  renderDash=function(){
    if(!LOGS.length){
      ['dc1','dc2','dashAlert','dc4'].forEach(function(id){document.getElementById(id).textContent='0'});
      document.getElementById('dc1f').textContent='当前源暂无数据 · 全任务 '+taskMeta().total.toLocaleString()+' 条';
      document.getElementById('dc2f').textContent='—';document.getElementById('dc3f').textContent='—';document.getElementById('dc4f').textContent='—';
      document.getElementById('dashSummary').innerHTML='<div class="summary-line">当前日志源暂无数据，请先导入或切换其他日志源。</div>';
      document.getElementById('dashHour').innerHTML='';document.getElementById('dashIp').innerHTML='';document.getElementById('dashList').innerHTML='';document.getElementById('dashPeakNote').textContent='';renderArch();return;
    }
    legacy.dash();
    // 告警数以服务端规则引擎为准，避免仪表盘与威胁分析页各算一套出现不同数字
    if(ALERT_CACHE&&ALERT_CACHE.source_id===CURRENT.id){
      document.getElementById('navAlert').textContent=ALERT_CACHE.total;
      document.getElementById('dashAlert').textContent=ALERT_CACHE.total;
      document.getElementById('dc3f').textContent=ALERT_CACHE.active_rules+' 类规则 · 服务端计算';
      document.getElementById('dashList').innerHTML=ALERT_CACHE.rules.map(function(item){
        var g=item.rule;return '<div class="r"><span class="k"><span class="tag '+sevCls(sevName(g.severity))+'">'+sevName(g.severity)+'</span>'+esc(g.name)+'</span><b style="color:var(--red)">'+item.count+'</b></div>';
      }).join('')+'<div class="r" style="border-top:1px solid var(--border);margin-top:6px;padding-top:10px"><span class="k"><b>合计</b></span><b>'+ALERT_CACHE.total+'</b></div>';
    }
  };
  renderStats=function(){
    if(LOGS.length){legacy.stats();return}
    var isWeb=!CURRENT||CURRENT.kind==='web';document.getElementById('statsWeb').style.display=isWeb?'':'none';document.getElementById('statsAlt').style.display=isWeb?'none':'';
    if(!isWeb){legacy.stats();return}
    ['sk1','sk2','sk3','sk4','sk5'].forEach(function(id){document.getElementById(id).textContent=id==='sk3'?'0%':'0'});
    ['sf1','sf2','sf5','ovPeak'].forEach(function(id){document.getElementById(id).textContent='暂无数据'});
    ['ovStatus','ovHour','ovHourLb','ovIp','ovPath','topList','freqRows','tmHour','tmHourLb','baseCmd','baseExfil','baseRows','ipRows','ipInOut','ipErrTop','pathRows','uaRows','stCards','st4path','st5path','netRows','soRef'].forEach(function(id){var el=document.getElementById(id);if(el)el.innerHTML=''});
  };

  renderAlerts=function(){
    if(!TASK_ID||!CURRENT)return;
    var source=CURRENT,taskId=TASK_ID,serial=++alertSerial;
    document.getElementById('alertBox').innerHTML='<div class="alerts-empty">正在按当前生效规则计算…</div>';
    api('/tasks/'+encodeURIComponent(taskId)+'/sources/'+encodeURIComponent(source.id)+'/alerts').then(function(data){
      if(serial!==alertSerial||taskId!==TASK_ID||!CURRENT||CURRENT.id!==source.id)return;
      ALERT_CACHE=data;
      var rows=data.rules.map(function(item){var g=workRules().filter(function(r){return r.id===item.rule.id})[0]||convertRule(item.rule);return {g:g,hits:item.hits,count:item.count}});
      var hiN=0,midN=0;rows.forEach(function(x){if(x.count){if(x.g.sev==='高')hiN++;else if(x.g.sev==='中')midN++}});
      var hitRules=rows.filter(function(x){return x.count}).length;
      var sum='<div class="alerts-sum"><span>生效规则 <b>'+rows.length+'</b> 条</span><span>命中 <b>'+data.total+'</b> 条</span><span>有命中的规则 <b>'+hitRules+'</b> 条</span><span>高危 <b style="color:var(--red)">'+hiN+'</b> · 中危 <b style="color:var(--amber)">'+midN+'</b></span><span id="toRules">去规则管理 →</span></div>';
      var body=rows.map(function(x){var g=x.g,hits=x.hits;
        return '<div class="rule-grp" data-rid="'+g.id+'"><div class="rule-hd"><span class="tag '+sevCls(g.sev)+'">'+esc(g.sev)+'</span><span class="nm">'+esc(g.name)+'</span><span class="cat">'+esc(g.cat||'')+'</span><span class="why">'+esc(g.why||'')+'</span><span class="toR" data-edit="'+g.id+'">规则</span><span class="n'+(x.count?'':' zero')+'">'+x.count+' 条命中</span></div>'+hits.slice(0,6).map(hitLine).join('')+(x.count>6?'<div class="hit" style="color:var(--faint);cursor:default">…共 '+x.count+' 条，界面仅展示前 6 条</div>':'')+'</div>';
      }).join('');
      document.getElementById('alertBox').innerHTML=sum+(body||'<div class="alerts-empty">当前日志源没有启用的规则</div>');
      document.getElementById('navAlert').textContent=data.total;document.getElementById('dashAlert').textContent=data.total;
      if(document.querySelector('.page.on')&&document.querySelector('.page.on').id==='p-dash')renderDash();
    }).catch(function(e){if(serial===alertSerial&&taskId===TASK_ID)document.getElementById('alertBox').innerHTML='<div class="alerts-empty">'+esc(e.message)+'</div>'});
  };
  updateAlertBadge=renderAlerts;

  function fillSources(){
    var html=SOURCES.map(function(s){return '<option value="'+esc(s.id)+'">'+esc(s.name)+'（'+s.count+' 条）</option>'}).join('');
    ['pasteSource','rSource'].forEach(function(id){var el=document.getElementById(id),old=el.value;el.innerHTML=html;if(old&&SOURCES.some(function(s){return s.id===old}))el.value=old;else if(CURRENT)el.value=CURRENT.id});
  }
  /* ===== 自定义 log_format 模板 =====
     内置 combined 正则是固定顺序，nginx 改过 log_format 就会漏字段或整行失败。
     这里把模板绑到日志源上，解析时优先用模板。 */
  // 字段英文名 → 中文。只此一份：重复 var 声明会互相覆盖，先前就踩过这个坑。
  var FIELD_LB={
    ts:'时间',ip:'来源 IP',xff:'XFF',host:'站点',method:'方法',path:'路径',status:'状态',bytes:'大小',
    protocol:'协议',action:'动作',elapsed:'耗时(ms)',cache:'缓存结果',url:'完整 URL',hier:'出口方式',
    level:'级别',thread:'线程',logger:'类名',pid:'进程号',frontend:'前端',backend:'后端',cost_ms:'耗时(ms)',
    ua:'UA',ref:'Referer',user:'账号',request:'请求行',
    type:'类型',cmd:'命令',eventId:'事件 ID',msg:'消息内容',srcip:'来源 IP',dstip:'目的 IP',
    srcport:'来源端口',dstport:'目的端口',
    request_time:'请求耗时',request_length:'请求长度',msec:'毫秒时间戳',connection:'连接号',
    connection_requests:'连接请求数',server_port:'服务端口',remote_port:'客户端端口',
    upstream_addr:'上游地址',upstream_status:'上游状态',upstream_response_time:'上游耗时',
    upstream_connect_time:'上游连接耗时',upstream_header_time:'上游首字节耗时',
    upstream_cache_status:'缓存状态',scheme:'协议',server_protocol:'HTTP 版本',http_host:'Host 头'
  };
  function currentFormat(){
    var sid=CURRENT&&CURRENT.id;if(!sid||!BOOT||!BOOT.formats)return null;
    for(var i=0;i<BOOT.formats.length;i++){
      if((BOOT.formats[i].source_ids||[]).indexOf(sid)>=0)return BOOT.formats[i];
    }
    return null;
  }
  function renderFormatBox(){
    var badge=document.getElementById('fmtBadge');if(!badge)return;
    var box=document.getElementById('fmtTemplate'),clear=document.getElementById('fmtClear'),hint=document.getElementById('fmtHint');
    var item=currentFormat();
    if(item){
      badge.className='tag ok';badge.textContent='自定义：'+item.name;
      var isRegex=(item.kind||'nginx')==='regex';
      if(document.activeElement!==box)box.value=isRegex?'':(item.template||'');
      clear.style.display='';
      hint.innerHTML=isRegex
        ? '当前源用的是正则模板（对方格式不是 nginx 语法），这里只做展示。要改正则请到左侧「日志模板」页编辑。'
        : '当前源按自定义模板解析，超出的变量存进扩展信息；内置 combined 的固定顺序不再生效。';
    }else{
      badge.className='tag lo';badge.textContent='内置 combined';
      if(document.activeElement!==box)box.value='';
      clear.style.display='none';
      hint.innerHTML='内置 combined 只认固定顺序：IP - - [时间] "请求" 状态 字节 "Referer" "UA"。若服务器自定义了 log_format（比如在末尾加了 XFF、站点），多出来的部分会被丢掉。';
    }
    document.getElementById('fmtResult').innerHTML='';
  }
  function formatNameOf(text){
    var m=/log_format\s+([A-Za-z0-9_]+)/i.exec(text||'');
    return m?m[1]:'custom';
  }
  function formatFieldsHTML(fields){
    return (fields||[]).map(function(f){return '<span class="chip c" title="'+esc(f)+'">'+esc(FIELD_LB[f]||f)+'</span>'}).join('');
  }
  function previewFormat(){
    var text=document.getElementById('fmtTemplate').value;
    var out=document.getElementById('fmtResult');
    if(!text.trim()){out.innerHTML='<div class="merr">先粘贴 log_format 再点识别</div>';return}
    var sample=LOGS.length?LOGS[0].raw:'';
    api('/formats/preview',{method:'POST',json:{template:text,text:sample}}).then(function(r){
      var html='<div style="font-size:11.5px;line-height:1.9">识别到 <b>'+r.fields.length+'</b> 个字段：'+formatFieldsHTML(r.fields);
      if(r.extra&&r.extra.length)html+='<div style="color:var(--muted);margin-top:2px">其中 '+r.extra.length+' 个是模板自带的变量，导入时会各建一列，可用于统计与筛选：'+esc(r.extra.join('、'))+'</div>';
      html+='</div>';
      if(r.rows.length){
        var row=r.rows[0],cells=[];
        Object.keys(row).forEach(function(k){
          if(k==='line_no'||k==='raw'||row[k]==null||row[k]==='')return;
          cells.push('<span style="margin-right:12px"><span style="color:var(--faint)">'+esc(FIELD_LB[k]||k)+'</span> <b>'+esc(k==='ts'?fmtTime(row[k]):row[k])+'</b></span>');
        });
        html+='<div style="margin-top:9px;font-size:11.5px">用当前源第一条日志试解析：</div>'
            +'<div style="margin-top:4px;padding:8px 10px;background:#1e1e1e;color:#e8e8e8;border-radius:7px;font-family:ui-monospace,Consolas,monospace;font-size:11px;line-height:1.6;word-break:break-all">'+esc(row.raw)+'</div>'
            +'<div style="margin-top:6px;font-size:11.5px;line-height:1.9">'+(cells.join('')||'<span style="color:var(--red)">没有取到任何字段</span>')+'</div>';
      }else if(sample){
        html+='<div style="margin-top:8px;font-size:11.5px;color:var(--amber);line-height:1.7">当前源的第一条日志与模板匹配不上。如果这批数据是改格式之前导入的，属于正常；新导入的日志会按模板解析。</div>';
      }else{
        html+='<div style="margin-top:8px;font-size:11.5px;color:var(--muted)">当前源还没有数据，导入后才能验证实际匹配效果</div>';
      }
      out.innerHTML=html;
    }).catch(function(e){out.innerHTML='<div class="merr">'+esc(e.message)+'</div>'});
  }
  function saveFormat(){
    var text=document.getElementById('fmtTemplate').value,status=document.getElementById('fmtStatus');
    if(!CURRENT){toast('先选择一个日志源');return}
    if(!text.trim()){toast('先粘贴 log_format');return}
    var sid=CURRENT.id,existing=currentFormat();
    var body={name:formatNameOf(text),template:text,source_ids:[sid]};
    if(existing)body.id=existing.id;   // 改的是同一份模板，别每次保存都新建
    api('/formats',{method:'POST',json:body}).then(function(item){
      BOOT.formats=(BOOT.formats||[]).filter(function(f){return (f.source_ids||[]).indexOf(sid)<0});
      BOOT.formats.push(item);
      renderFormatBox();
      status.textContent='已绑定到「'+CURRENT.name+'」，下次导入按新格式解析';
      var moved=(item.detached||[]).filter(function(m){return m.name!==item.name});
      if(moved.length)toast('模板已保存；从「'+moved.map(function(m){return m.name}).join('、')+'」上摘下了相同日志源');
      else toast('模板已保存');
    }).catch(function(e){status.textContent='';document.getElementById('fmtResult').innerHTML='<div class="merr">'+esc(e.message)+'</div>'});
  }
  function clearFormat(){
    var item=currentFormat();if(!item)return;
    var others=(item.source_ids||[]).filter(function(s){return s!==CURRENT.id});
    if(others.length){
      // 模板是共享的，删掉会把别人的绑定一起带走，这里只提示不动手
      toast('该模板还绑着 '+others.map(sourceNameById).join('、')+'，请到「日志模板」页处理');
      return;
    }
    api('/formats/'+encodeURIComponent(item.id),{method:'DELETE'}).then(function(){
      BOOT.formats=(BOOT.formats||[]).filter(function(f){return f.id!==item.id});
      renderFormatBox();toast('已恢复内置 combined');
    }).catch(function(e){toast(e.message)});
  }
  bind('fmtPreview','click',previewFormat);
  bind('fmtSave','click',saveFormat);
  bind('fmtClear','click',clearFormat);

  function nullWarn(i){
    if(!i.warnings||!i.warnings.length)return '';
    var lines=i.warnings.map(function(w){
      var effect=w.field==='ts'?'时间线、时间筛选、频次窗口都会失效':'排行、频次分析、规则匹配会拿不到该字段';
      return '「'+(FIELD_LB[w.field]||w.field)+'」'+Math.round(w.ratio*100)+'% 为空（'+w.nulls+'/'+i.rows+'）· '+effect;
    });
    return '<div class="imp-warn">可能是日志格式与该解析器不匹配：'+lines.join('；')+'</div>';
  }

  function nullWarnText(result){
    if(!result.warnings||!result.warnings.length)return '';
    return '；但 ' + result.warnings.map(function(w){return (FIELD_LB[w.field]||w.field)+' 整列为空'}).join('、') + '，格式可能与该解析器不匹配';
  }

  function missText(result){
    if(!result.failed)return '';
    if(result.rows===0)return '；当前日志未识别，全部 '+result.failed+' 行未能解析，处理办法见下方导入记录';
    return '；'+result.failed+' 行未识别';
  }

  function tplForSource(sid){
    var list=BOOT.formats||[];
    for(var i=0;i<list.length;i++){if((list[i].source_ids||[]).indexOf(sid)>=0)return list[i]}
    return null;
  }

  // 解析不了的行：说清楚是"格式没认出来"，并给出可落地的下一步。
  // 只有 combined 支持日志模板，别的格式说"去加模板"会把人带偏。
  function importHint(i){
    if(!i.failed)return '';
    var scope=i.rows===0?('全部 '+i.failed+' 行未识别'):(i.failed+' 行未识别');
    var head='当前日志未识别（'+scope+'）';
    if(i.format!=='combined')return '<div class="imp-warn">'+head+'：该格式没有可配置模板，请核对该日志源选用的解析格式</div>';
    var tpl=tplForSource(i.source_id);
    if(tpl)return '<div class="imp-warn">'+head+'：已绑定模板「'+esc(tpl.name)+'」但仍有行匹配不上，检查模板是否粘贴完整</div>';
    return '<div class="imp-warn">'+head+'：请在上方「日志格式」面板粘贴 log_format 并保存绑定'
      +'<div class="imp-path" data-copy="'+esc(BOOT.format_dir||'')+'" title="点击复制路径">模板目录：'+esc(BOOT.format_dir||'formats/')+'</div></div>';
  }

  function copyText(text,quiet){
    var done=function(){if(!quiet)toast('已复制')};
    var fail=function(){if(!quiet)toast('复制失败，请手动选中')};
    // 同步 execCommand 优先：在点击手势内一定被浏览器放行，clipboard API 在
    // 某些环境（无焦点、权限策略）会静默 reject，用户会觉得「点了没反应」
    var ok=false;
    try{
      var ta=document.createElement('textarea');
      ta.value=text;ta.setAttribute('readonly','');ta.style.cssText='position:fixed;left:-9999px;top:0;opacity:0';
      document.body.appendChild(ta);ta.focus();ta.select();ta.setSelectionRange(0,text.length);
      ok=document.execCommand('copy');
      document.body.removeChild(ta);
    }catch(e){ok=false}
    if(ok){done();return true}
    if(navigator.clipboard&&navigator.clipboard.writeText){
      navigator.clipboard.writeText(text).then(done).catch(fail);
      return true;
    }
    fail();
    return false;
  }

  function renderImportForms(){
    fillSources();if(!TASK_DATA)return;
    var imports=TASK_DATA.imports||[],list=document.getElementById('importList');
    document.getElementById('importCount').textContent=imports.length+' 个';
    list.innerHTML=imports.map(function(i){
      var badge=importBadge(i),err=i.errors&&i.errors.length?'<div style="font-size:11px;color:var(--red);margin-top:3px">首个错误：第 '+i.errors[0].line+' 行 · '+esc(i.errors[0].error)+'</div>':'';
      var warn=nullWarn(i),hint=importHint(i);
      return '<div class="imp-row"><span class="chip c">'+esc(i.format)+'</span><div class="imp-main"><div style="font-size:12.8px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(i.filename)+'">'+esc(i.filename)+'</div><div style="font-size:11.5px;color:var(--muted);margin-top:3px">'+esc(sourceNameById(i.source_id))+' · '+i.rows+' 行入库 · '+i.failed+' 行失败 · '+fmtSize(i.size||0)+' · '+esc(fmtTime(i.created_at))+'</div>'+err+hint+warn+'</div><span class="tag '+badge.cls+'">'+esc(badge.text)+'</span><button class="icobtn danger" data-del-imp="'+esc(i.id)+'" title="删除这次导入"><svg viewBox="0 0 12 12"><path d="M3.2 3.2l5.6 5.6M8.8 3.2l-5.6 5.6" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg></button></div>';
    }).join('')||'<div class="imp-row" style="color:var(--faint)">当前任务尚未导入日志</div>';
    list.onclick=function(e){
      var btn=e.target.closest?e.target.closest('[data-del-imp]'):null;
      if(btn){deleteImportFlow(btn.getAttribute('data-del-imp'));return}
      var path=e.target.closest?e.target.closest('[data-copy]'):null;
      if(path)copyText(path.getAttribute('data-copy'));
    };
  }
  function requireTask(){if(TASK_ID)return true;if(!BOOT){toast('后端尚未连接，请先启动 LogWarden 服务');return false}openTaskModal();return false}
  /* ===== 本地导入：入口全部在清单行内（拖入 / 选择文件） =====
     这里只保留共用的文件过滤、文件夹递归收集和隐藏的文件选择输入。 */
  var fileInput=document.getElementById('fileInput');
  var MAX_FILE=500*1024*1024;
  function isLogish(path){
    var name=String(path||'').split(/[\\/]/).pop();
    if(!name||name.charAt(0)==='.')return false;
    if(name.indexOf('.')<0)return true;               // secure、messages 这类无扩展名日志
    return /\.(log|txt|gz|json|xml|csv|evtx|out|dat|journal)$/i.test(name);
  }
  function collectDirEntries(items,cb){
    var out=[],root=Array.prototype.slice.call(items).map(function(i){return i.webkitGetAsEntry&&i.webkitGetAsEntry()}).filter(Boolean);
    if(!root.length){cb([],false);return}
    var doneCount=0;
    function walk(entry,path,done){
      if(entry.isFile){entry.file(function(f){out.push({file:f,path:path+f.name});done()},done);return}
      var reader=entry.createReader(),batch=[];
      function read(){
        reader.readEntries(function(arr){
          if(!arr.length){
            if(!batch.length){done();return}
            var left=batch.length,n=0;
            batch.forEach(function(e){walk(e,path+entry.name+'/',function(){if(++n===left)done()})});
            return;
          }
          batch=batch.concat(Array.prototype.slice.call(arr));read();
        },done);
      }
      read();
    }
    root.forEach(function(e){walk(e,'',function(){if(++doneCount===root.length)cb(out,true)})});
  }
  fileInput.onchange=function(){
    var list=Array.prototype.map.call(fileInput.files,function(f){return {file:f,path:f.name}});
    fileInput.value='';
    if(NEED_PICK_SRC){var sid=NEED_PICK_SRC;NEED_PICK_SRC=null;importToSource(sid,list);}
  };
  function pastePayload(){return {source_id:document.getElementById('pasteSource').value,fmt:document.getElementById('pasteFormat').value,text:document.getElementById('pasteBox').value}}
  document.getElementById('btnPasteParse').onclick=function(){
    if(!requireTask())return;var data=pastePayload();if(!data.text.trim()){toast('请先粘贴日志');return}
    var serial=++previewSerial;
    api('/preview',{method:'POST',json:data}).then(function(result){
      if(serial!==previewSerial)return;
      document.getElementById('pasteStatus').textContent='预览 '+result.rows.length+' 行 · 错误 '+result.errors.length+' 行';
      var preview=result.rows.slice(0,5).map(function(r){return '<div class="rc-code" style="margin:6px 0">第 '+r.line_no+' 行\n'+esc(JSON.stringify(r,null,2))+'</div>'}).join('');
      var errors=result.errors.slice(0,3).map(function(r){return '<div style="color:var(--red);font-size:12px;padding:5px">第 '+r.line+' 行：'+esc(r.error)+'</div>'}).join('');
      document.getElementById('pasteResult').innerHTML=preview+errors;
    }).catch(function(e){toast(e.message)});
  };
  document.getElementById('btnPasteImport').onclick=function(){
    var btn=this;if(btn.disabled)return;
    if(!requireTask())return;var data=pastePayload();if(!data.text.trim()){toast('请先粘贴日志');return}
    var taskId=TASK_ID;btn.disabled=true;
    api('/tasks/'+encodeURIComponent(taskId)+'/imports/text',{method:'POST',json:data}).then(function(result){
      toast('已入库 '+result.rows+' 行，失败 '+result.failed+' 行'+missText(result)+nullWarnText(result));if(taskId===TASK_ID)return loadTask(taskId,data.source_id);
    }).catch(function(e){toast(e.message)}).then(function(){btn.disabled=false});
  };
  /* ===== 远程拉取：SSH/SFTP · SMB · HTTP =====
     凭据只在这次请求里带过去，不写 localStorage；进度靠轮询 job，不占连接。 */
  var R_PROTO='ssh',R_JOB=null,R_TIMER=null;
  var PROTO_CFG={
    ssh:{port:22,path:'/var/log/nginx/access.log',hostLb:'主机',hostPh:'IP 或域名',
         hostTip:'SSH 默认 22',pathTip:'支持通配 access.log-*，多个轮转文件按时间拼接'},
    smb:{port:445,path:'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx',hostLb:'主机',hostPh:'IP 或主机名',
         hostTip:'SMB 默认 445',pathTip:'\\\\主机\\共享\\目录\\*.log，或 C:\\Windows\\... 自动转 UNC'},
    http:{port:80,path:'/logs/access.log',hostLb:'主机 / URL',hostPh:'http://10.0.0.5:8080',
         hostTip:'可带 scheme，走 HTTPS 就写 https://',pathTip:'URL 的路径部分；HTTP 不支持通配'}
  };
  function srcById(id){for(var i=0;i<SOURCES.length;i++)if(SOURCES[i].id===id)return SOURCES[i];return null}
  function remotePayload(){
    return {
      protocol:R_PROTO,
      host:document.getElementById('rHost').value.trim(),
      port:document.getElementById('rPort').value.trim(),
      username:document.getElementById('rUser').value.trim(),
      auth:R_PROTO==='http'?'password':document.getElementById('rAuth').value,
      password:document.getElementById('rPass').value,
      key_path:document.getElementById('rKey').value.trim(),
      key_text:document.getElementById('rKeyText').value,
      path:document.getElementById('rPath').value.trim()
    };
  }
  function applyProto(){
    var cfg=PROTO_CFG[R_PROTO],http=R_PROTO==='http';
    document.getElementById('rPort').value=cfg.port;
    document.getElementById('rPath').value=cfg.path;
    document.getElementById('rPathTip').textContent=cfg.pathTip;
    document.getElementById('rHostTip').textContent=cfg.hostTip;
    document.getElementById('rHostLb').textContent=cfg.hostLb;
    document.getElementById('rHost').placeholder=cfg.hostPh;
    // HTTP 没有密钥和会话的区分，用户名密码就是 Basic 认证
    document.getElementById('rAuthWrap').style.display=http?'none':'';
    syncAuthFields();
  }
  function syncAuthFields(){
    var mode=R_PROTO==='http'?'password':document.getElementById('rAuth').value;
    document.getElementById('rPassWrap').style.display=mode==='password'?'':'none';
    document.getElementById('rKeyWrap').style.display=mode==='key'?'':'none';
    document.getElementById('rKeyTextWrap').style.display=mode==='key'?'':'none';
  }
  document.getElementById('proto').onclick=function(e){
    var box=e.target.closest?e.target.closest('[data-proto]'):null;if(!box)return;
    R_PROTO=box.getAttribute('data-proto');
    Array.prototype.forEach.call(this.children,function(c){c.classList.toggle('on',c===box)});
    applyProto();
  };
  document.getElementById('rAuth').onchange=syncAuthFields;
  document.getElementById('rSource').onchange=function(){
    var s=srcById(this.value);if(!s)return;
    var first=(s.paths||[])[0];
    if(first)document.getElementById('rPath').value=first;
    document.getElementById('rFmt').value=s.format||'';
  };
  function escLine(text){return text.length>70?text.slice(0,70)+'…':text}
  function setProg(pct,text){
    pct=Math.max(0,Math.min(100,pct|0));
    document.getElementById('progBar').style.width=pct+'%';
    document.getElementById('progPc').textContent=pct+'%';
    if(text!=null)document.getElementById('progTx').textContent=escLine(String(text));
  }
  function probeHtml(r){
    var files=(r.files||[]).slice(0,8).map(function(f){
      return '<div style="font-size:11.5px;color:var(--muted)">'+esc(f.name)+' · '+fmtSize(f.size)+'</div>';
    }).join('');
    if((r.files||[]).length>8)files+='<div style="font-size:11.5px;color:var(--faint)">…共 '+r.files_total+' 个</div>';
    var sample=(r.sample||[]).map(function(l){
      return '<div class="rc-code" style="margin:4px 0;padding:6px 8px">'+esc(l)+'</div>';
    }).join('');
    var notes=(r.notes||[]).map(function(n){
      return '<div style="color:#92400e;font-size:11.5px">· '+esc(n)+'</div>';
    }).join('');
    return '<div><span class="ok">已连通</span> · '+esc(r.banner||r.target)+' · 耗时 '+r.elapsed+'s</div>'+
      '<div style="margin-top:6px">文件 <span class="k">'+r.files_total+'</span> 个 · 共 <span class="k">'+fmtSize(r.total_size)+'</span> · 约 <span class="k">'+(r.est_lines||0).toLocaleString()+'</span> 行</div>'+
      files+notes+
      (sample?'<div style="margin-top:8px;font-size:11.5px;color:var(--muted)">前 '+r.sample.length+' 行</div>'+sample:'');
  }
  document.getElementById('btnProbe').onclick=function(){
    var btn=this;if(btn.disabled)return;
    var data=remotePayload();
    if(!data.host){toast('请填写主机');return}
    var box=document.getElementById('probeBox');
    btn.disabled=true;box.className='probe on';box.innerHTML='<span class="k">连接中…</span>';
    api('/remote/probe',{method:'POST',json:data}).then(function(r){
      box.innerHTML=probeHtml(r);
    }).catch(function(e){
      box.className='probe on';box.innerHTML='<span class="bad">连接失败</span> · '+esc(e.message);
    }).then(function(){btn.disabled=false});
  };
  function watchJob(id){
    if(R_TIMER)clearInterval(R_TIMER);
    var btn=document.getElementById('btnPull'),cancel=document.getElementById('btnCancel');
    btn.disabled=true;cancel.style.display='';
    R_TIMER=setInterval(function(){
      api('/remote/jobs/'+encodeURIComponent(id)).then(function(s){
        setProg(s.percent,s.message);
        if(s.state==='pending'||s.state==='running')return;
        clearInterval(R_TIMER);R_TIMER=null;R_JOB=null;
        btn.disabled=false;cancel.style.display='none';
        if(s.state==='done'){
          setProg(100,s.message);
          toast('已入库 '+s.rows+' 行，失败 '+s.failed+' 行');
          var sid=document.getElementById('rSource').value;
          if(TASK_ID===null||!sid)return;
          document.getElementById('probeBox').className='probe on';
          document.getElementById('probeBox').innerHTML='<div><span class="ok">拉取完成</span> · '+esc(s.target)+' · 用时 '+s.elapsed+'s</div><div style="margin-top:5px">入库 <span class="k">'+s.rows+'</span> 行 · 失败 '+s.failed+' 行 · '+fmtSize(s.bytes_total)+'</div>';
          loadTask(TASK_ID,sid);
        }else if(s.state==='cancelled'){
          toast('已取消，已提交的批次留在库里，可在导入记录里删除');
        }else{
          document.getElementById('probeBox').className='probe on';
          document.getElementById('probeBox').innerHTML='<span class="bad">拉取失败</span> · '+esc(s.error||'未知错误');
          toast(s.error||'拉取失败');
        }
      }).catch(function(e){
        clearInterval(R_TIMER);R_TIMER=null;R_JOB=null;
        btn.disabled=false;cancel.style.display='none';toast(e.message);
      });
    },400);
  }
  document.getElementById('btnPull').onclick=function(){
    var btn=this;if(btn.disabled)return;
    if(!requireTask())return;
    var sid=document.getElementById('rSource').value;
    if(!sid){toast('请选择归入哪个日志源');return}
    var data=remotePayload();
    if(!data.host){toast('请填写主机');return}
    data.task_id=TASK_ID;data.source_id=sid;
    data.fmt=document.getElementById('rFmt').value;
    data.encoding=document.getElementById('rEncoding').value;
    btn.disabled=true;
    document.getElementById('probeBox').className='probe';
    document.getElementById('progBox').className='prog on';
    setProg(0,'正在建立连接…');
    api('/remote/pull',{method:'POST',json:data}).then(function(job){
      R_JOB=job.id;watchJob(job.id);
    }).catch(function(e){btn.disabled=false;document.getElementById('progBox').className='prog';toast(e.message)});
  };
  document.getElementById('btnCancel').onclick=function(){
    var btn=this;if(!R_JOB||btn.disabled)return;
    btn.disabled=true;
    api('/remote/jobs/'+encodeURIComponent(R_JOB)+'/cancel',{method:'POST'})
      .catch(function(e){toast(e.message)}).then(function(){btn.disabled=false});
  };

  function ntComponentsChecked(){
    var out=[];document.querySelectorAll('#ntComponents input:checked').forEach(function(cb){out.push(cb.value)});return out;
  }
  function updateNtSum(){
    var sum=document.getElementById('ntSrcSum'),box=document.getElementById('ntSources');
    if(!sum||!box)return;
    var rows=box.querySelectorAll('input[data-src]');
    if(!rows.length){sum.textContent='';return}
    var all={required:0,recommended:0,optional:0},on={required:0,recommended:0,optional:0},picked=0;
    Array.prototype.forEach.call(rows,function(cb){
      var lv=cb.getAttribute('data-lv');
      if(lv!=='required'&&lv!=='recommended'&&lv!=='optional')lv='optional';
      all[lv]++;if(cb.checked){on[lv]++;picked++}
    });
    var total=rows.length;
    var seg=[];
    ['required','recommended','optional'].forEach(function(k){
      if(all[k])seg.push((k==='required'?'必要项':k==='recommended'?'推荐项':'可选项')+' '+on[k]+'/'+all[k]);
    });
    sum.textContent='已勾 '+picked+' / '+total+' 项 · '+seg.join(' · ')+(picked?'':' · 至少勾一项');
  }
  function renderNtSources(){
    var box=document.getElementById('ntSources');if(!box||!BOOT)return;
    var comps=ntComponentsChecked();
    if(!comps.length){box.innerHTML='<div style="font-size:11.5px;color:var(--faint);padding:8px 2px">先在上面勾选组件</div>';updateNtSum();return}
    var seen={},html='';
    comps.forEach(function(cid){
      var comp=null;BOOT.components.forEach(function(c){if(c.id===cid)comp=c});
      if(!comp)return;
      var rows=[];
      (comp.sources||[]).forEach(function(sid){
        if(seen[sid])return;seen[sid]=1;
        var s=null;BOOT.sources.forEach(function(x){if(x.id===sid)s=x});
        if(!s)return;
        // 默认勾选：必要项与推荐项都勾，可选项留给人自己决定；enabled_by_default=false 的仍不勾（要先在系统里开启）
        var defChecked=s.level!=='optional'&&s.enabled_by_default!==false;
        var checked=NT_SRC[sid]!==undefined?NT_SRC[sid]:defChecked;
        var lv=s.level==='required'?'<span class="ntlv req">必要项</span>':s.level==='recommended'?'<span class="ntlv rec">推荐项</span>':'<span class="ntlv opt">可选项</span>';
        rows.push('<label class="ntrow"><input type="checkbox" data-src="'+esc(sid)+'" data-lv="'+esc(s.level||'recommended')+'"'+(checked?' checked':'')+'><span class="nm">'+esc(s.name)+'</span>'+lv+'<span class="pt">'+esc((s.paths||[])[0]||'')+'</span></label>');
      });
      if(rows.length)html+='<div class="ntgrp">'+esc(comp.name)+'</div>'+rows.join('');
    });
    box.innerHTML=html||'<div style="font-size:11.5px;color:var(--faint);padding:8px 2px">所选组件没有可收集的日志源</div>';
    box.onchange=function(e){
      var cb=e.target;if(!cb||cb.tagName!=='INPUT')return;
      NT_SRC[cb.getAttribute('data-src')]=cb.checked;updateNtSum();
    };
    updateNtSum();
  }
  function openTaskModal(){
    if(!BOOT)return;
    var tpl=document.getElementById('ntTemplate');
    tpl.innerHTML='<option value="">自定义组合</option>'+BOOT.templates.map(function(t){return '<option value="'+esc(t.id)+'">'+esc(t.name)+'</option>'}).join('');
    var groups={};BOOT.components.forEach(function(c){(groups[c.group]=groups[c.group]||[]).push(c)});
    document.getElementById('ntComponents').innerHTML=Object.keys(groups).map(function(g){return '<div style="grid-column:1/-1;color:var(--pri-d);font-size:11px;font-weight:700;margin-top:5px">'+esc(g)+'</div>'+groups[g].map(function(c){return '<label style="display:flex;gap:6px;align-items:center;font-size:12px;color:var(--text);margin:0"><input type="checkbox" value="'+esc(c.id)+'" style="width:14px;height:14px;margin:0;accent-color:var(--pri)">'+esc(c.name)+'</label>'}).join('')}).join('');
    document.getElementById('ntComponents').onchange=function(){renderNtSources()};
    NT_SRC={};renderNtSources();
    document.getElementById('ntErr').textContent='';document.getElementById('taskModal').classList.add('on');
    if(!document.getElementById('ntName').value){var d=new Date();document.getElementById('ntName').value=d.getFullYear()+String(d.getMonth()+1).padStart(2,'0')+String(d.getDate()).padStart(2,'0')+'-入侵排查'}
  }
  document.getElementById('newTask').onclick=openTaskModal;
  document.getElementById('ntCancel').onclick=function(){document.getElementById('taskModal').classList.remove('on')};
  document.getElementById('ntTemplate').onchange=function(){
    var id=this.value,t=null;BOOT.templates.forEach(function(x){if(x.id===id)t=x});
    document.querySelectorAll('#ntComponents input').forEach(function(cb){cb.checked=!!(t&&t.components.indexOf(cb.value)>=0)});
    renderNtSources();
  };
  document.getElementById('ntSave').onclick=function(){
    var name=document.getElementById('ntName').value.trim(),components=ntComponentsChecked();
    if(!name){document.getElementById('ntErr').textContent='任务名称不能为空';return}
    if(!components.length){document.getElementById('ntErr').textContent='至少选择一个组件';return}
    var source_ids=[];
    document.querySelectorAll('#ntSources input[data-src]:checked').forEach(function(cb){source_ids.push(cb.getAttribute('data-src'))});
    if(!source_ids.length){document.getElementById('ntErr').textContent='至少勾选一项要收集的日志';return}
    var template=document.getElementById('ntTemplate').value;
    api('/tasks',{method:'POST',json:{name:name,template_id:template,components:components,source_ids:source_ids}}).then(function(task){
      document.getElementById('taskModal').classList.remove('on');BOOT.tasks.unshift(task);
      var miss=0,need=0;
      (task.evidence||[]).forEach(function(c){
        c.logs.forEach(function(l){
          if(l.state==='off')return;
          // 与后端一致：该组件有必要项就只数必要项，否则数推荐项
          if(c.basis==='required'&&l.level!=='required')return;
          if(c.basis==='recommended'&&l.level!=='recommended')return;
          need++;if(l.state==='miss')miss++;
        });
      });
      return loadTask(task.id).then(function(){showPage('import');toast(miss?'任务已创建，当前统计级别还缺 '+miss+' 项，按清单逐个导即可':'任务已创建，当前统计级别的日志已齐，可以开始排查')});
    }).catch(function(e){document.getElementById('ntErr').textContent=e.message});
  };
  document.getElementById('topImport').onclick=function(){if(requireTask())showPage('import')};
  document.getElementById('setDelTask').onclick=function(){deleteTaskFlow(TASK_ID)};
  /* 归档：软删除的任务保留数据文件，没有恢复入口就成了看不见又占空间的僵尸数据 */
  var archivedOpen=false;
  function loadArchived(open){
    var box=document.getElementById('archivedList'),btn=document.getElementById('setArchived');
    if(!box||!btn)return Promise.resolve();
    return api('/deleted-tasks').then(function(items){
      btn.textContent='查看归档（'+items.length+'）';
      if(open===undefined)archivedOpen=!archivedOpen;
      else archivedOpen=open;
      box.style.display=archivedOpen?'':'none';
      if(!archivedOpen)return;
      box.innerHTML=items.map(function(t){
        return '<div class="imp-row"><div class="imp-main"><div style="font-size:12.8px;font-weight:600">'+esc(t.name)+'</div><div style="font-size:11.5px;color:var(--muted);margin-top:3px">移出于 '+esc(fmtTime(t.updated_at))+' · 数据文件仍在 data/ 下</div></div><button class="btn sm" data-restore="'+esc(t.id)+'">恢复</button></div>';
      }).join('')||'<div class="imp-row" style="color:var(--faint)">没有已归档的任务</div>';
    }).catch(function(e){toast(e.message)});
  }
  document.getElementById('setArchived').onclick=function(){loadArchived()};
  document.getElementById('archivedList').onclick=function(e){
    var btn=e.target.closest?e.target.closest('[data-restore]'):null;if(!btn)return;
    var id=btn.getAttribute('data-restore');btn.disabled=true;
    api('/tasks/'+encodeURIComponent(id)+'/restore',{method:'POST'}).then(function(){
      return api('/bootstrap').then(function(data){
        BOOT.tasks=data.tasks;renderTaskList();return loadArchived(false);
      });
    }).then(function(){toast('任务已恢复')}).catch(function(err){btn.disabled=false;toast(err.message)});
  };
  /* ===== 日志模板管理页 =====
     模板原来只藏在导入页的一个面板里：看不到有几套、各绑了哪些源、哪个源还空着。
     这里把绑定关系摊开，顺带能建自定义日志源（复用解析器，不用改代码）。 */
  var FMT_EDITING = null;

  function fmtItems(){return (BOOT&&BOOT.formats)||[]}

  // 只有 combined / tomcat 走 log_format 模板；w3c 靠 #Fields 自描述，配模板没用
  function tplCapableSources(){
    return ((BOOT&&BOOT.sources)||[]).filter(function(s){
      return s.format==='combined'||s.format==='tomcat';
    });
  }
  function boundSourceIds(){
    var set={};
    fmtItems().forEach(function(f){(f.source_ids||[]).forEach(function(sid){set[sid]=1})});
    return set;
  }
  // 模板一行摘要：kind 决定看 pattern 还是 log_format 原文
  function fmtBody(f){
    if((f.kind||'nginx')==='regex')return f.pattern||'';
    return f.template||'';
  }
  function fmtFieldNames(f){
    var body=fmtBody(f),out=[],seen={};
    if((f.kind||'nginx')==='regex'){
      var re=/\(\?P<([A-Za-z_][A-Za-z0-9_]*)>/g,m;
      while((m=re.exec(body))){if(!seen[m[1]]){seen[m[1]]=1;out.push(m[1])}}
    }else{
      var re2=/\$([A-Za-z_][A-Za-z0-9_]*)/g,m2;
      while((m2=re2.exec(body))){if(!seen[m2[1]]){seen[m2[1]]=1;out.push(m2[1])}}
    }
    return out;
  }
  function fmtKindLabel(f){return (f.kind||'nginx')==='regex'?'正则':'log_format'}

  function renderFormatsPage(){
    var box=document.getElementById('fmtList');
    if(!box)return;
    var items=fmtItems(),bound=boundSourceIds();
    var q=((document.getElementById('fq')||{}).value||'').trim().toLowerCase();
    var shown=items.filter(function(f){
      if(!q)return true;
      var hay=(f.name+' '+fmtKindLabel(f)+' '+(f.source_ids||[]).map(sourceNameById).join(' ')+' '+fmtBody(f)).toLowerCase();
      return hay.indexOf(q)>=0;
    });
    document.getElementById('navFormat').textContent=items.length;
    document.getElementById('fStat').textContent=items.length+' 个模板 · 已绑定 '+Object.keys(bound).length+' 个源';
    box.innerHTML=shown.map(function(f){
      var srcs=(f.source_ids||[]).map(function(sid){return '<span class="tag ok">'+esc(sourceNameById(sid))+'</span>'}).join(' ');
      var names=fmtFieldNames(f);
      return '<div class="rule-row">'
        +'<div style="flex:1;min-width:0">'
        +'<div class="nm" style="width:auto">'+esc(f.name)
        +' <span class="tag '+(f.kind==='regex'?'md':'lo')+'" style="margin-left:4px">'+fmtKindLabel(f)+'</span>'
        +' <span style="font-weight:400;color:var(--faint);font-size:11px">'+names.length+' 个字段'+(names.length?'：'+esc(names.slice(0,6).join(' / '))+(names.length>6?' …':''):'')+'</span></div>'
        +'<div style="font-size:11.5px;color:var(--muted);margin-top:5px">'+(srcs||'<span style="color:var(--red)">未绑定源</span>')+'</div>'
        +'<div class="fmt-tpl" title="'+esc(fmtBody(f))+'">'+esc(fmtBody(f))+'</div>'
        +(f.note?'<div style="font-size:11px;color:var(--muted);margin-top:3px">'+esc(f.note)+'</div>':'')
        +'<div style="font-size:11px;color:var(--faint);margin-top:4px">更新于 '+esc(fmtTime(f.updated_at||f.created_at))+'</div>'
        +'</div>'
        +'<button class="btn sm" data-fedit="'+esc(f.id)+'">编辑</button>'
        +'<button class="btn sm danger" data-fdel="'+esc(f.id)+'">删除</button>'
        +'</div>';
    }).join('')||'<div class="rule-row" style="color:var(--faint)">'+(items.length?'没有匹配的模板':'还没有模板。点右上角「新建模板」，粘一行日志点「识别」就能自动生成')+'</div>';
    renderUnboundSources(bound);
  }

  function renderUnboundSources(bound){
    var box=document.getElementById('fmtUnbound');
    if(!box)return;
    var all=tplCapableSources(),free=all.filter(function(s){return !bound[s.id]});
    if(!all.length){
      box.innerHTML='<div class="rule-row" style="color:var(--faint)">当前没有需要模板的日志源</div>';
      return;
    }
    if(!free.length){
      box.innerHTML='<div class="rule-row" style="color:var(--faint)">可配模板的日志源都已绑定</div>';
      return;
    }
    box.innerHTML=free.map(function(s){
      return '<div class="rule-row"><div style="flex:1;min-width:0">'
        +'<div style="font-size:12.8px;font-weight:600">'+esc(s.name)+'</div>'
        +'<div style="font-size:11.5px;color:var(--muted);margin-top:3px">'+esc(s.id)+' · 解析格式 '+esc(s.format)+'</div>'
        +'</div><button class="btn sm" data-fbind="'+esc(s.id)+'">配模板</button></div>';
    }).join('');
  }

  /* ---- 内置格式参考：系统已经认识哪些日志形状 ---- */
  var PRESETS=null;
  function renderPresets(){
    var box=document.getElementById('fmtPresets');
    if(!box)return;
    var ready=PRESETS?Promise.resolve(PRESETS):api('/formats/presets').then(function(list){PRESETS=list;return list});
    ready.then(function(list){
      var hint=document.getElementById('fPresetHint');
      if(hint)hint.textContent=list.length+' 类常见日志；没列到的，粘一行日志点「识别」，或照右侧 JSON 自己写';
      box.innerHTML=list.map(function(p){
        var tag=p.kind==='none'?'<span class="tag lo">无需模板</span>'
          :(p.kind==='nginx'?'<span class="tag ok">log_format</span>':'<span class="tag md">正则</span>');
        var meta=(p.fields||[]).length?'<span class="pmeta">'+p.fields.length+' 个字段</span>':'';
        var btns=p.kind==='none'?''
          :'<span class="pbtns"><button class="btn sm" data-ptest="'+esc(p.key)+'">试解析</button>'
           +'<button class="btn sm pri" data-preset="'+esc(p.key)+'">保存</button></span>';
        var cols='<div class="pgrid">'
          +'<div><div class="plb">日志示例</div><pre class="psample">'+esc(p.sample||'')+'</pre></div>';
        if(p.code){
          var rows=Math.max(6,Math.min(20,(p.code||'').split('\n').length));
          cols+='<div><div class="plb">模板 JSON（直接改）</div>'
            +'<textarea class="pjson" data-pkey="'+esc(p.key)+'" rows="'+rows+'" spellcheck="false">'+esc(p.code)+'</textarea></div>';
        }
        cols+='</div>';
        var fields=(p.fields||[]).length
          ? '<div class="pd">字段 '+p.fields.map(function(f){return '<span class="chip c">'+esc(FIELD_LB[f]||f)+'</span>'}).join('')+'</div>'
          : '';
        return '<div class="preset"><div class="ph"><b>'+esc(p.vendor)+'</b>'+tag+meta+btns+'</div>'
          +cols
          +(p.note?'<div class="pd">'+esc(p.note)+'</div>':'')+fields
          +'<div class="ptest" id="ptest-'+esc(p.key)+'"></div></div>';
      }).join('')||'<div class="preset" style="color:var(--faint)">没有可参考的格式</div>';
    }).catch(function(e){box.innerHTML='<div class="preset"><span style="color:var(--red)">'+esc(e.message)+'</span></div>'});
  }

  // 读卡片里被改过的 JSON
  function presetSpec(key){
    var ta=document.querySelector('#fmtPresets textarea[data-pkey="'+key+'"]');
    if(!ta)throw new Error('找不到这条的 JSON');
    var spec;
    try{spec=JSON.parse(ta.value)}
    catch(e){throw new Error('JSON 语法错误：'+e.message)}
    if(!spec||typeof spec!=='object'||Array.isArray(spec))throw new Error('最外层必须是 { ... } 对象');
    return spec;
  }
  function testPreset(key){
    var out=document.getElementById('ptest-'+key);
    var p=(PRESETS||[]).filter(function(x){return x.key===key})[0];
    var spec;
    try{spec=presetSpec(key)}
    catch(e){if(out)out.innerHTML='<span style="color:var(--red)">'+esc(e.message)+'</span>';return}
    if(!out)return;
    out.innerHTML='<span style="color:var(--muted)">解析中…</span>';
    api('/formats/preview',{method:'POST',json:{spec:spec,text:(p&&p.sample)||''}}).then(function(r){
      if(!r.rows.length){
        out.innerHTML='<span style="color:var(--red)">示例日志解析失败：'+esc((r.errors[0]||{}).error||'没有取到字段')+'</span>';
        return;
      }
      var row=r.rows[0],cells=[];
      Object.keys(row).forEach(function(k){
        if(k==='line_no'||k==='raw'||row[k]==null||row[k]==='')return;
        cells.push('<span style="margin-right:12px"><span style="color:var(--faint)">'+esc(FIELD_LB[k]||k)+'</span> <b>'+esc(k==='ts'?fmtTime(row[k]):row[k])+'</b></span>');
      });
      out.innerHTML='<div style="margin-top:7px;padding-top:7px;border-top:1px dashed var(--border)">匹配示例，共 '+r.fields.length+' 个字段：'+(cells.join('')||'<span style="color:var(--red)">没取到值</span>')+'</div>';
    }).catch(function(e){out.innerHTML='<span style="color:var(--red)">'+esc(e.message)+'</span>'});
  }
  function savePreset(key){
    var spec;
    try{spec=presetSpec(key)}catch(e){toast(e.message);return}
    // 没绑源就转到弹窗：那里有勾选框，也还能再改
    if(!(spec.source_ids||[]).length){
      openFmtModal(null);
      writeSpec(spec);
      renderFmtSourcePicker(spec.source_ids||[]);
      document.getElementById('fmPreview').innerHTML='<span style="color:var(--muted)">已带上你改过的 JSON。勾选要挂的日志源，再点「试解析」确认，最后保存。</span>';
      return;
    }
    api('/formats',{method:'POST',json:spec}).then(function(item){
      return refreshFormats().then(function(){toast('模板「'+item.name+'」已保存到上方列表')});
    }).catch(function(e){toast(e.message)});
  }

  function renderFmtSourcePicker(selected){
    var box=document.getElementById('fmSources');
    if(!box)return;
    var sel={};(selected||[]).forEach(function(s){sel[s]=1});
    var list=tplCapableSources();
    box.innerHTML=list.map(function(s){
      return '<label class="ntrow" title="'+esc(s.name)+'（'+esc(s.id)+'）"><input type="checkbox" value="'+esc(s.id)+'"'+(sel[s.id]?' checked':'')+'>'
        +'<span class="sname">'+esc(s.name)+'</span><span class="sid">'+esc(s.id)+'</span></label>';
    }).join('')||'<div style="font-size:11.5px;color:var(--faint);padding:4px">没有可配模板的源，先点「新建日志源」建一个</div>';
  }

  /* ---- 模板 JSON 编辑 ---- */
  var FM_KEYS=['name','kind','template','pattern','time_format','types','note','source_ids'];

  // 固定 key 顺序，方便肉眼看 diff；空值不写进 JSON，免得一片 null
  function orderedSpec(src){
    var out={};
    FM_KEYS.forEach(function(k){
      var v=src?src[k]:undefined;
      if(v===undefined||v===null||v==='')return;
      if(typeof v==='object'&&!Array.isArray(v)&&!Object.keys(v).length)return;
      out[k]=v;
    });
    return out;
  }
  function writeSpec(spec){document.getElementById('fmJson').value=JSON.stringify(orderedSpec(spec),null,2)}
  function readSpec(){
    var txt=document.getElementById('fmJson').value,spec;
    try{spec=JSON.parse(txt)}
    catch(e){throw new Error('JSON 语法错误：'+e.message)}
    if(!spec||typeof spec!=='object'||Array.isArray(spec))throw new Error('最外层必须是 { ... } 形式的对象');
    return spec;
  }
  function pickedSources(){
    return [].slice.call(document.querySelectorAll('#fmSources input[type=checkbox]'))
      .filter(function(x){return x.checked}).map(function(x){return x.value});
  }
  function sampleLine(){
    var v=(document.getElementById('fmSample').value||'').trim();
    if(v)return v;
    if(CURRENT&&CURRENT.rows&&CURRENT.rows.length)return CURRENT.rows[0].raw||'';
    return '';
  }
  function fieldCells(row){
    var cells=[];
    Object.keys(row).forEach(function(k){
      if(k==='line_no'||k==='raw'||row[k]==null||row[k]==='')return;
      cells.push('<span style="margin-right:12px"><span style="color:var(--faint)">'+esc(FIELD_LB[k]||k)+'</span> <b>'+esc(k==='ts'?fmtTime(row[k]):row[k])+'</b></span>');
    });
    return cells.join('');
  }

  function renderFmtDoc(){
    var box=document.getElementById('fmtDoc');
    if(!box)return;
    if(box.getAttribute('data-ready'))return;
    api('/formats/help').then(function(r){
      var h=[];
      h.push('<h5>两种写法，二选一</h5>');
      h.push('<p><b>kind: "nginx"</b>　把整段 log_format 粘进 <code>template</code>，$变量 自动编译。nginx 和兼容 nginx 语法的网关走这个。</p>');
      h.push('<p><b>kind: "regex"</b>　自己写正则，<code>(?P&lt;名字&gt;...)</code> 就是字段名。Apache、Tomcat、Caddy、自研应用，只要正则能切出字段就能解析。</p>');
      (r.samples||[]).forEach(function(s){
        h.push('<p style="margin-top:9px"><b>'+esc(s.title)+'</b></p><pre>'+esc(s.text)+'</pre>');
      });
      h.push('<h5>字段名用下面这些，下游功能才认得</h5>');
      h.push('<p><code>ip</code> 来源 IP　<code>ts</code> 时间　<code>request</code> 请求行（自动拆成 method + path）　<code>method</code>　<code>path</code>　<code>status</code> 状态码　<code>bytes</code> 大小　<code>ua</code>　<code>ref</code>　<code>xff</code>　<code>host</code>　<code>user</code></p>');
      h.push('<p>其他任意名字（<code>cost_ms</code>、<code>upstream_addr</code>…）导入时各建一列，能筛选、能排行；但「频次分析 / 路径基线 / 规则引擎」只认上面那些标准名。</p>');
      h.push('<h5>可选项</h5>');
      h.push('<p><code>time_format</code>　时间格式，Python strptime 写法，如 <code>%d/%b/%Y:%H:%M:%S %z</code>。不写就按内置几种常见格式依次试。</p>');
      h.push('<p><code>types</code>　强制列类型：<code>{"cost_ms": "INTEGER", "ratio": "REAL"}</code>。不写按字段名推断，认不出当文本。</p>');
      h.push('<p><code>note</code>　备注，显示在列表里，不影响解析。</p>');
      h.push('<h5>写正则的四条</h5>');
      h.push('<p>① 用 <code>^</code> 开头，<b>不要加 <code>$</code></b>：日志尾部常有额外字段，加了就整条匹配不上。</p>');
      h.push('<p>② 取值给明确形状：<code>[^"]*</code>、<code>\\S+</code>、<code>\\d{3}</code>。相邻两个 <code>.+?</code> 会互相抢字符。</p>');
      h.push('<p>③ JSON 里反斜杠要写两个：<code>\\\\S</code> 实际是正则的 <code>\\S</code>。</p>');
      h.push('<p>④ 引号里的值不用自己剥：<code>"(?P&lt;ua&gt;[^"]*)"</code> 取出来就是干净的。</p>');
      box.innerHTML=h.join('');
      box.setAttribute('data-ready','1');
    }).catch(function(e){box.innerHTML='<span style="color:var(--red)">说明加载失败：'+esc(e.message)+'</span>'});
  }

  function openFmtModal(formatId, presetSource){
    FMT_EDITING = formatId ? (fmtItems().filter(function(f){return f.id===formatId})[0]||null) : null;
    if(formatId&&!FMT_EDITING){toast('模板不存在');return}
    document.getElementById('fmTitle').textContent=FMT_EDITING?'编辑模板':'新建模板';
    document.getElementById('fmKind').textContent=FMT_EDITING?FMT_EDITING.id:'';
    document.getElementById('fmErr').textContent='';
    document.getElementById('fmSample').value='';
    var spec;
    if(FMT_EDITING){
      spec=orderedSpec(FMT_EDITING);
      writeSpec(spec);
    }else{
      // 新建给完整骨架：空值也留着，用户一眼能看到有哪些键可填
      spec={name:'',kind:'regex',pattern:'',time_format:'',types:{},note:'',
        source_ids:(presetSource?[presetSource]:[])};
      document.getElementById('fmJson').value=JSON.stringify(spec,null,2);
    }
    renderFmtSourcePicker(spec.source_ids||[]);
    renderFmtDoc();
    document.getElementById('fmPreview').innerHTML=FMT_EDITING?''
      :'<span style="color:var(--muted)">先粘一行日志点「识别」自动生成 pattern，或直接照下方说明自己写。字段名对了，「试解析」就能看到拆出来的值。</span>';
    document.getElementById('fmtModal').classList.add('on');
  }

  function detectFmt(){
    var out=document.getElementById('fmPreview');
    var line=sampleLine();
    if(!line){out.innerHTML='<span style="color:var(--red)">先粘一行日志；日志浏览里选中一个有数据的源时，会自动用它的第一条</span>';return}
    out.innerHTML='<span style="color:var(--muted)">识别中…</span>';
    api('/formats/detect',{method:'POST',json:{line:line}}).then(function(r){
      if(r.kind!=='regex'){
        out.innerHTML='<div><b>'+esc(r.vendor)+'</b></div>'
          +'<div style="color:var(--muted);margin-top:5px;line-height:1.8">'+esc(r.note||'')+'</div>';
        return;
      }
      var spec={};
      try{spec=readSpec()}catch(e){}
      var keepName=String(spec.name||'').trim();
      writeSpec({
        name:keepName||('自动识别 · '+String(r.vendor||'').split('（')[0].trim()),
        kind:'regex',
        pattern:r.pattern,
        time_format:r.time_format||'',
        note:spec.note||'',
        source_ids:pickedSources().length?pickedSources():(spec.source_ids||[])
      });
      var html='<div><b>识别为：'+esc(r.vendor)+'</b></div>'
        +'<div style="margin-top:5px">'+formatFieldsHTML(r.fields)+'</div>'
        +'<div style="margin-top:6px">'+fieldCells(r.sample||{})+'</div>'
        +'<div style="margin-top:6px;color:var(--muted);font-size:11.5px;line-height:1.75">'+esc(r.note||'')+'</div>';
      out.innerHTML=html;
    }).catch(function(e){out.innerHTML='<span style="color:var(--red)">'+esc(e.message)+'</span>'});
  }

  function previewFmt(){
    var out=document.getElementById('fmPreview'),spec;
    try{spec=readSpec()}
    catch(e){out.innerHTML='<span style="color:var(--red)">'+esc(e.message)+'</span>';return}
    var line=sampleLine();
    if(!line){out.innerHTML='<span style="color:var(--red)">没有可试解析的日志：在上方输入框粘一行，或先选中一个有数据的日志源</span>';return}
    if(spec.source_ids&&!spec.source_ids.length&&!pickedSources().length)delete spec.source_ids;
    api('/formats/preview',{method:'POST',json:{spec:spec,text:line}}).then(function(r){
      var html='<div>解析出 <b>'+r.fields.length+'</b> 个字段：'+formatFieldsHTML(r.fields)+'</div>';
      if(r.extra&&r.extra.length)html+='<div style="color:var(--muted);margin-top:2px">其中 '+r.extra.length+' 个是模板自带的，导入时各建一列：'+esc(r.extra.join('、'))+'</div>';
      if(r.rows.length){
        html+='<div style="margin-top:8px;font-size:11.5px;color:var(--muted)">匹配的日志：</div>'
          +'<div style="margin-top:3px;padding:7px 10px;background:#1e1e1e;color:#e8e8e8;border-radius:7px;font-family:ui-monospace,Consolas,monospace;font-size:10.5px;line-height:1.6;word-break:break-all">'+esc(r.rows[0].raw)+'</div>'
          +'<div style="margin-top:6px">'+(fieldCells(r.rows[0])||'<span style="color:var(--red)">没有取到任何字段</span>')+'</div>';
      }else{
        html+='<div style="margin-top:6px;color:var(--amber)">正则能编译，但这行日志匹配不上。重点查：开头要不要 <code>^</code>、字段之间空格数、引号有没有包含进去。</div>';
      }
      out.innerHTML=html;
    }).catch(function(e){out.innerHTML='<span style="color:var(--red)">'+esc(e.message)+'</span>'});
  }

  function saveFmt(){
    var err=document.getElementById('fmErr');
    err.textContent='';
    var spec;
    try{spec=readSpec()}
    catch(e){err.textContent=e.message;return}
    var picked=pickedSources();
    if(picked.length)spec.source_ids=picked;
    if(!String(spec.name||'').trim()){err.textContent='name 不能为空，给模板起个名字（如 main、apache-combined）';return}
    if(!(spec.source_ids||[]).length){err.textContent='至少要勾选一个日志源';return}
    if(FMT_EDITING)spec.id=FMT_EDITING.id;
    api('/formats',{method:'POST',json:spec}).then(function(item){
      var moved=item.detached||[];
      closeFmtModal();
      return refreshFormats().then(function(){
        toast(moved.length?'模板已保存；从「'+moved.map(function(m){return m.name}).join('、')+'」上摘下了相同日志源':'模板已保存');
      });
    }).catch(function(e){err.textContent=e.message});
  }

  // 勾选框改动 → 写回 JSON 的 source_ids
  function syncSpecSources(){
    try{
      var spec=readSpec(),picked=pickedSources(),before=spec.source_ids||[];
      if(before.length===picked.length&&before.every(function(x,i){return x===picked[i]}))return;
      spec.source_ids=picked;
      writeSpec(spec);
    }catch(e){}   // JSON 还没写完时不动，等用户改对
  }
  // JSON 里改了 source_ids → 反同步勾选框
  var JSON_SYNC_TIMER=null;
  function syncPickerFromJson(){
    clearTimeout(JSON_SYNC_TIMER);
    JSON_SYNC_TIMER=setTimeout(function(){
      try{renderFmtSourcePicker(readSpec().source_ids||[])}catch(e){}
    },450);
  }

  function closeFmtModal(){document.getElementById('fmtModal').classList.remove('on')}

  function delFmt(id){
    var f=fmtItems().filter(function(x){return x.id===id})[0];
    if(!f)return;
    var names=(f.source_ids||[]).map(sourceNameById).join('、');
    if(!confirm('删除模板「'+f.name+'」？\n\n绑定的源会回到内置解析规则：'+(names||'（无）')+'\n\n已入库的数据不受影响。'))return;
    api('/formats/'+encodeURIComponent(id),{method:'DELETE'}).then(function(){
      return refreshFormats().then(function(){toast('模板已删除')});
    }).catch(function(e){toast(e.message)});
  }

  function refreshFormats(){
    return api('/bootstrap').then(function(data){
      BOOT=data;
      var cur=document.querySelector('#p-formats');
      if(cur&&cur.classList.contains('on'))renderFormatsPage();
      renderFormatBox();
    });
  }

  /* ---- 自定义日志源 ---- */
  var FORMAT_OPTIONS=[['combined','combined（nginx/Apache 通用格式）'],['w3c','w3c（IIS）'],['syslog','syslog'],['json','JSON 行'],['text','纯文本'],['audit','auditd'],['firewall','防火墙 key=value'],['shell','shell history']];
  function openSrcModal(){
    document.getElementById('smTitle').textContent='新建日志源';
    document.getElementById('smErr').textContent='';
    ['smId','smName','smPaths','smValue'].forEach(function(id){document.getElementById(id).value=''});
    document.getElementById('smLevel').value='recommended';
    document.getElementById('smFormat').innerHTML=FORMAT_OPTIONS.map(function(x){
      return '<option value="'+x[0]+'">'+x[1]+'</option>';
    }).join('');
    document.getElementById('srcModal').classList.add('on');
  }
  function closeSrcModal(){document.getElementById('srcModal').classList.remove('on')}
  function saveSrc(){
    var err=document.getElementById('smErr');
    err.textContent='';
    var body={
      id:document.getElementById('smId').value.trim().toLowerCase(),
      name:document.getElementById('smName').value.trim(),
      format:document.getElementById('smFormat').value,
      level:document.getElementById('smLevel').value,
      paths:document.getElementById('smPaths').value.split(',').map(function(s){return s.trim()}).filter(Boolean),
      value:document.getElementById('smValue').value.trim(),
      group:'app'
    };
    api('/sources/custom',{method:'POST',json:body}).then(function(item){
      closeSrcModal();
      return refreshFormats().then(function(){
        toast('日志源「'+item.name+'」已保存，可在导入页选择');
        openFmtModal(null,item.id);
      });
    }).catch(function(e){err.textContent=e.message});
  }

  // 逐个绑定并容错：一个 id 写错不该让后面的初始化整条断掉
  function bind(id,event,fn){
    var el=document.getElementById(id);
    if(el)el.addEventListener(event,fn);
  }
  bind('fq','input',function(){renderFormatsPage()});
  bind('fNew','click',function(){openFmtModal(null)});
  bind('fNewSource','click',openSrcModal);
  bind('fmTest','click',previewFmt);
  bind('fmSave','click',saveFmt);
  bind('fmCancel','click',closeFmtModal);
  bind('fmDetect','click',detectFmt);
  bind('fmJson','input',syncPickerFromJson);
  bind('fmSources','change',syncSpecSources);
  bind('smSave','click',saveSrc);
  bind('smCancel','click',closeSrcModal);
  bind('fmtList','click',function(e){
    var ed=e.target.closest?e.target.closest('[data-fedit]'):null;
    var dl=e.target.closest?e.target.closest('[data-fdel]'):null;
    if(ed){openFmtModal(ed.getAttribute('data-fedit'));return}
    if(dl)delFmt(dl.getAttribute('data-fdel'));
  });
  bind('fmtUnbound','click',function(e){
    var b=e.target.closest?e.target.closest('[data-fbind]'):null;
    if(b)openFmtModal(null,b.getAttribute('data-fbind'));
  });
  bind('fmtPresets','click',function(e){
    var t=e.target.closest?e.target:null;
    if(!t)return;
    var tb=t.closest('[data-ptest]');
    if(tb){testPreset(tb.getAttribute('data-ptest'));return}
    var sb=t.closest('[data-preset]');
    if(sb)savePreset(sb.getAttribute('data-preset'));
  });

  var baseShowPage=showPage;
  showPage=function(p){baseShowPage(p);if(p==='set'){loadArchived(false);fillBaselineForm()}if(p==='formats'){renderFormatsPage();renderPresets()}};

  /* ===== 基线判定阈值 =====
     ratio 以规则 ws_size_shift 的 agg.ratio_lt 为准：只改 localStorage 会让界面和
     规则引擎各用一套阈值，出现「界面标红、告警列表里没有」。 */
  function syncBaselineFromRule(){
    var agg=typeof baselineRuleAgg==='function'?baselineRuleAgg():null;
    var v=agg?Number(agg.ratio_lt):NaN;
    if(isFinite(v)&&v>0)BASELINE_CFG.ratio=v;
  }
  function fillBaselineForm(){
    if(!document.getElementById('bsCmd'))return;
    var agg=typeof baselineRuleAgg==='function'?baselineRuleAgg():null;
    document.getElementById('bsCmd').value=BASELINE_CFG.cmdMaxBytes;
    document.getElementById('bsExfil').value=Math.round(BASELINE_CFG.exfilMinBytes/1024);
    document.getElementById('bsMin').value=BASELINE_CFG.minSamples;
    var r=agg?Number(agg.ratio_lt):NaN,m=agg?Number(agg.min_samples):NaN;
    document.getElementById('bsRatio').value=isFinite(r)&&r>0?r:BASELINE_DEFAULT.ratio;
    document.getElementById('bsSamples').value=isFinite(m)&&m>0?m:BASELINE_DEFAULT.ruleSamples;
    document.getElementById('bsErr').textContent='';
  }
  function ruleWithAgg(raw,ratio,samples){
    var next=copyObj(raw),agg=copyObj(raw.match.agg);
    agg.ratio_lt=ratio;agg.min_samples=Math.round(samples);
    next.match={agg:agg};
    return next;
  }
  function saveBaselineForm(){
    var err=document.getElementById('bsErr');
    var cmd=Number(document.getElementById('bsCmd').value);
    var exfilKb=Number(document.getElementById('bsExfil').value);
    var ratio=Number(document.getElementById('bsRatio').value);
    var minN=Number(document.getElementById('bsMin').value);
    var samples=Number(document.getElementById('bsSamples').value);
    if(!(cmd>=1&&cmd<=1048576)){err.textContent='命令执行上限需在 1 B 到 1 MB 之间';return null}
    if(!(exfilKb>=1&&exfilKb<=1048576)){err.textContent='数据外带下限需在 1 KB 到 1 GB 之间';return null}
    if(!(ratio>0&&ratio<1)){err.textContent='体积突变比例需在 0 到 1 之间（不含 0 和 1）';return null}
    if(!(minN>=2)){err.textContent='基线表最小请求数不能小于 2';return null}
    if(!(samples>=3)){err.textContent='规则最小样本数不能小于 3';return null}
    err.textContent='';
    BASELINE_CFG.cmdMaxBytes=Math.round(cmd);
    BASELINE_CFG.exfilMinBytes=Math.round(exfilKb*1024);
    BASELINE_CFG.minSamples=Math.round(minN);
    BASELINE_CFG.ratio=ratio;
    saveBaselineCfg();
    var raw=typeof baselineRuleRaw==='function'?baselineRuleRaw():null;
    if(!raw){if(LOGS.length)renderStats();toast('界面阈值已保存；未找到规则 ws_size_shift，规则侧未更新');return null}
    return api('/rules/ws_size_shift',{method:'PUT',json:ruleWithAgg(raw,ratio,samples)}).then(function(){
      return loadRules();
    }).then(function(){
      syncBaselineFromRule();fillBaselineForm();
      if(LOGS.length)renderStats();
      renderAlerts();
      toast('阈值已保存，界面与规则引擎同时生效');
    }).catch(function(e){err.textContent=e.message});
  }
  document.getElementById('bsSave').onclick=saveBaselineForm;
  document.getElementById('bsReset').onclick=function(){
    var err=document.getElementById('bsErr');
    BASELINE_CFG.cmdMaxBytes=BASELINE_DEFAULT.cmdMaxBytes;
    BASELINE_CFG.exfilMinBytes=BASELINE_DEFAULT.exfilMinBytes;
    BASELINE_CFG.minSamples=BASELINE_DEFAULT.minSamples;
    BASELINE_CFG.ratio=BASELINE_DEFAULT.ratio;
    saveBaselineCfg();
    var raw=typeof baselineRuleRaw==='function'?baselineRuleRaw():null;
    if(!raw){fillBaselineForm();if(LOGS.length)renderStats();toast('已恢复默认阈值');return}
    api('/rules/ws_size_shift',{method:'PUT',json:ruleWithAgg(raw,BASELINE_DEFAULT.ratio,BASELINE_DEFAULT.ruleSamples)}).then(function(){
      return loadRules();
    }).then(function(){
      syncBaselineFromRule();fillBaselineForm();
      if(LOGS.length)renderStats();renderAlerts();
      toast('已恢复默认阈值');
    }).catch(function(e){err.textContent=e.message});
  };
  /* ---- 证据清单左抽屉：当前架构下全部可收集源，勾选即增删 ---- */
  function eviOpen(){
    renderEviDrawer();
    document.getElementById('eviDrawer').classList.add('on');
    document.getElementById('eviShade').classList.add('on');
  }
  function eviClose(){
    document.getElementById('eviDrawer').classList.remove('on');
    document.getElementById('eviShade').classList.remove('on');
  }
  function renderEviDrawer(){
    var sub=document.getElementById('eviDrawerSub');
    if(sub)sub.textContent=(TASK_DATA&&TASK_DATA.arch?TASK_DATA.arch+' · ':'')+'勾选决定收哪些，级别决定缺了是否影响结论';
    var sel={};((TASK_DATA&&TASK_DATA.source_ids)||[]).forEach(function(s){sel[s]=1});
    var counts=(TASK_DATA&&TASK_DATA.stats&&TASK_DATA.stats.source_counts)||{};
    var body=document.getElementById('eviDrawerBody');if(!body)return;
    var html='';
    ((TASK_DATA&&TASK_DATA.components)||[]).forEach(function(cid){
      var c=null;(BOOT.components||[]).forEach(function(x){if(x.id===cid)c=x});
      if(!c)return;
      html+='<div class="evi-comp">'+esc(c.name)+(c.desc?'<span class="d">'+esc(c.desc)+'</span>':'')+'</div>';
      (c.sources||[]).forEach(function(sid){
        var s=null;(BOOT.sources||[]).forEach(function(x){if(x.id===sid)s=x});
        if(!s)return;
        var on=!!sel[sid],n=counts[sid]||0;
        var key=s.level||'recommended';
        var lvc=key==='required'?'req':key==='optional'?'opt':'rec';
        var st=n?('已导入 '+n+' 条'):(s.enabled_by_default===false?'默认未开启':'未导入');
        html+='<label class="evi-row'+(on?'':' off')+'" title="'+esc(s.name)+' · '+esc((s.paths||[]).join(' · '))+'">'
          +'<input type="checkbox" data-evisrc="'+esc(sid)+'"'+(on?' checked':'')+'>'
          +'<span class="ntlv '+lvc+'">'+esc(levelOf({level:key}).lb)+'</span>'
          +'<span class="n">'+esc(s.name)+'</span>'
          +'<span class="c">'+st+'</span>'
          +'</label>';
      });
    });
    body.innerHTML=html||'<div class="evi-full" style="color:#64748b;font-size:12px;padding:12px 0">该任务没有组件目录，无法展示清单</div>';
    body.onchange=function(e){
      var cb=e.target.closest?e.target.closest('input[data-evisrc]'):null;if(!cb)return;
      toggleEviSource(cb.getAttribute('data-evisrc'),cb.checked,cb);
    };
  }
  function toggleEviSource(sid,on,cb){
    var cur={};((TASK_DATA&&TASK_DATA.source_ids)||[]).forEach(function(s){cur[s]=1});
    if(!on&&cur[sid]){
      var n=(TASK_DATA.stats&&TASK_DATA.stats.source_counts&&TASK_DATA.stats.source_counts[sid])||0;
      if(n&&!confirm('「'+sid+'」已导入 '+n+' 条。\n\n取消后从清单和源列表隐藏，数据保留，重新勾选即恢复。确定取消？')){
        cb.checked=true;return;
      }
    }
    if(on)cur[sid]=1;else delete cur[sid];
    var ids=Object.keys(cur);
    if(!ids.length){cb.checked=false;toast('至少保留一个日志源');return}
    api('/tasks/'+encodeURIComponent(TASK_ID)+'/sources',{method:'PATCH',json:{source_ids:ids}})
      .then(function(data){
        applyTask(data);
        renderEviDrawer();
        toast(on?'已加入清单，可去导入页拉日志':'已从清单移除（数据保留）');
      })
      .catch(function(e){cb.checked=!on;toast(e.message)});
  }
  document.getElementById('viewEvidence').onclick=eviOpen;
  document.getElementById('eviClose').onclick=eviClose;
  document.getElementById('eviShade').onclick=eviClose;
  document.addEventListener('keydown',function(e){
    if(e.key==='Escape'&&document.getElementById('eviDrawer').classList.contains('on'))eviClose();
  });

  function replaceButton(id,handler){var old=document.getElementById(id),node=old.cloneNode(true);old.parentNode.replaceChild(node,old);node.addEventListener('click',handler);return node}
  replaceButton('rResetAll',function(){
    var b=this;if(b.getAttribute('data-armed')==='1'){api('/rules/reset',{method:'POST'}).then(refreshAfterRuleChange);b.removeAttribute('data-armed');b.textContent='重置';return}
    b.setAttribute('data-armed','1');b.textContent='确认恢复默认？';setTimeout(function(){b.removeAttribute('data-armed');b.textContent='重置'},2600);
  });
  replaceButton('rImport',function(){
    var input=document.createElement('input');input.type='file';input.accept='.json,application/json';
    input.onchange=function(){var file=input.files[0];if(!file)return;var reader=new FileReader();reader.onload=function(){
      try{var data=JSON.parse(reader.result),items=data.rules||data;if(!Array.isArray(items))throw new Error('格式不对');var chain=Promise.resolve(),count=0;
        items.forEach(function(item){if(!item.name)return;var raw=item._raw||item;if(!raw.match){var re=item.re||item.body||'$^',field=item.field||'raw';raw={name:item.name,category:item.cat||'导入',category_name:item.cat||'导入',severity:sevValue(item.sev||item.severity||'中'),priority:item.prio||item.priority||50,kind:'row',scope:item.applies&&item.applies.length===1?item.applies[0]:(item.applies&&item.applies.length?item.applies:'all'),explain:item.why||'导入规则',false_positive:item.why||'请结合业务确认',enabled:item.enabled!==false,match:{}};raw.match[field==='any'?'raw':field]={iregex:re}}
        delete raw.id;delete raw.builtin;chain=chain.then(function(){return api('/rules',{method:'POST',json:raw})});count++});
        chain.then(refreshAfterRuleChange).then(function(){toast('已导入 '+count+' 条规则')}).catch(function(e){toast(e.message)});
      }catch(e){toast('导入失败：'+e.message)}
    };reader.readAsText(file,'utf-8')};input.click();
  });

  replaceButton('tmRun',function(){
    var sid=document.getElementById('tmSrc').value,txt=document.getElementById('tmText').value;
    var src=null;SOURCES.forEach(function(s){if(s.id===sid)src=s});
    if(!src||!txt.trim()){document.getElementById('tmRes').innerHTML='<div class="t"><span class="miss">请先选择日志源并填样本文本</span></div>';return}
    document.getElementById('tmRes').innerHTML='<div class="t">正在用真实解析器与后端规则测试…</div>';
    api('/preview',{method:'POST',json:{source_id:sid,fmt:src.format,text:txt}}).then(function(preview){
      if(!preview.rows.length)throw new Error(preview.errors.length?preview.errors[0].error:'样本没有解析出记录');
      return api('/rules/test',{method:'POST',json:{sample:preview.rows[0],kind:src.kind}});
    }).then(function(items){
      var hit=items.filter(function(x){return x.hit}),miss=items.filter(function(x){return !x.hit});
      function line(x){return '<div class="t"><span class="tag '+sevCls(sevName(x.severity))+'">'+sevName(x.severity)+'</span><span class="nm">'+esc(x.name)+'</span><span class="'+(x.hit?'hit':'miss')+'">'+(x.hit?'命中':'未命中')+'</span></div>'}
      document.getElementById('tmRes').innerHTML='<div style="padding:7px 11px;font-size:11.5px;color:var(--faint)">真实单行规则：命中 '+hit.length+' · 未命中 '+miss.length+'；聚合规则需用事件序列验证</div>'+items.map(line).join('');
    }).catch(function(e){document.getElementById('tmRes').innerHTML='<div class="t"><span class="miss">'+esc(e.message)+'</span></div>'});
  });
  replaceButton('tmSample',function(){
    if(!TASK_ID)return;var sid=document.getElementById('tmSrc').value;
    api('/tasks/'+encodeURIComponent(TASK_ID)+'/query',{method:'POST',json:{source_id:sid,size:1,sort:{k:'id',dir:1}}}).then(function(page){
      if(!page.rows.length){toast('该日志源没有可取样本');return}
      document.getElementById('tmText').value=page.rows[0].raw||'';
    }).catch(function(e){toast(e.message)});
  });

  api('/bootstrap').then(function(data){
    BOOT=data;renderTaskList();return loadRules();
  }).then(function(){
    loadArchived(false);
  }).then(function(){
    var id=localStorage.getItem('logview.current.task'),exists=false;BOOT.tasks.forEach(function(t){if(t.id===id)exists=true});
    if(!exists)id=BOOT.tasks.length?BOOT.tasks[0].id:null;
    if(id)return loadTask(id);
    localStorage.removeItem('logview.current.task');openTaskModal();
  }).then(function(){
    // ?nt=1 直接打开新建任务；&sel=centos,nginx 预选组件；&evi=1 打开证据清单抽屉（AI 操盘入口）
    if(/[?&]nt=1/.test(location.search)){
      openTaskModal();
      var m=/[?&]sel=([^&]+)/.exec(location.search);
      if(m){
        var ids=decodeURIComponent(m[1]).split(',');
        document.querySelectorAll('#ntComponents input').forEach(function(cb){cb.checked=ids.indexOf(cb.value)>=0});
        renderNtSources();
      }
    }else if(/[?&]evi=1/.test(location.search)&&TASK_ID){
      eviOpen();
    }else{
      var pm=/[?&]pg=([a-z]+)/.exec(location.search);
      if(pm)showPage(pm[1]);   // AI 操盘直达：?pg=import / logs / stats / alerts / rules
    }
  }).catch(function(e){window.LOGVIEW_FATAL='后端连接失败：'+e.message;document.getElementById('pageSub').textContent=window.LOGVIEW_FATAL;toast(window.LOGVIEW_FATAL)});
})();
