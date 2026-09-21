# 代码安全审计报告：ylinux_old-master

- **生成时间**：2026-09-19 18:26
- **审计对象**：`ylinux_old-master`
- **审计方式**：静态分析（不执行被审代码）；静态引擎 + LLM Agent 数据流推理 + 独立对抗验证
- **Agent 运行**：50 轮 / 86,323 tokens / 604s（状态：concluded）

## 一、执行摘要

在 40 个在审文件中，**七类风险中的 7 类完成了实质审查**，记录有效问题 **10** 条：

- 🔴 **CRITICAL**：1 条
- 🟠 **HIGH**：2 条
- 🟡 **MEDIUM**：5 条
- 🔵 **LOW**：2 条

> **结论可信度**：3 条结论需要人工确认才能定案。详见第二节。

## 二、覆盖度与局限性

本节说明**这份报告没有覆盖什么**。审计结论的可信度直接取决于此——一份不声明边界的报告，其结论无法被正确使用。

### 2.1 七类风险覆盖矩阵

| 风险类 | 状态 | 发现 | 依据 |
|---|---|---|---|
| ✅ C1_注入 | covered | 3 | — |
| ✅ C2_反序列化 | no_issue | — | 在审项目中不存在 pickle/marshal/yaml.load/eval/exec/__import__ 形式的反序列化入口：对 app/** 做过一次覆盖式搜索，命中项全部是正则编译；XMLRPC 与模板渲染的解析路径也已逐处确认不涉及 Python 对象反序列化。会话序列化的实现位于内嵌库（非项目代码），不计入本项目漏洞。结论：无发现。 |
| ✅ C3_认证授权 | covered | 4 | — |
| ✅ C4_凭据配置 | covered | 2 | — |
| ✅ C5_文件路径 | covered | 1 | — |
| ✅ C6_依赖供应链 | no_issue | — | 供应链面只包含两部分：(1) 内嵌在 lib/ 下的第三方库（markdown、django_xmlrpc、sessions 等），按归因规则其自身缺陷不计入项目漏洞，本报告只声明归因；(2) 项目自身的依赖声明 —— settings.py 与 lib/__init__.py 中未见任何指向不存在/幻觉包名的依赖引入，也没有远程拉取代码的执行（无 pip install、无 curl\|bash |
| ✅ C7_AI代码特有 | covered | 1 | — |

### 2.2 静态引擎覆盖与实际盲区

**semgrep**：分析 292 个文件，命中 11 条。

**bandit**：分析 96 个文件，命中 22 条。

⚠️ **9 个文件完全未被该引擎分析**（Bandit 使用 Py3 ast，无法解析这些文件的语法（实测：它会读文件、数行数、记入 metrics，然后一条都不报））：

- `app/account/__init__.py`
- `app/sessions/backends/base.py` — vendored
- `app/sessions/models.py` — vendored
- `app/ydata/views.py`
- `app/ylab/views.py`
- `lib/django_xmlrpc/views.py` — vendored
- `lib/markdown/__init__.py` — vendored
- `lib/markdown/commandline.py` — vendored
- `scripts/ylinux-client.py`

**secret**：分析 91 个文件，命中 1 条。

**凭据扫描的特别说明**：下面命中的是**真实存在的凭据**，不是有风险的写法。因此处置方式是**轮换凭据**而不是修改代码——密钥一旦进入过版本历史，改掉当前文件并不能使它失效。本报告不包含任何凭据明文，清单见附录的「凭据清单」一节。

本轮命中 **1** 条凭据候选（覆盖 91 个文件）。

**未纳入审计范围的目录/文件**（8 项）：测试桩、生成物、依赖目录等。

### 2.3 Agent 运行状态

Agent 通过收口检查：七类覆盖度均已落终态、全部引擎候选已处置、所有 HIGH/CRITICAL 已提交独立对抗验证。

- ⚠️ **3 条验证后结论为「静态无法定论、需人工复核」**——这**不等于**已验证通过，是验证者把判断退回给了人。这些条目在人工核验前不应作为决策依据。

- 上下文压缩 11 次（压缩后以账本为准，不影响结论的确定性）

### 2.4 方法学固有局限

- **静态分析不执行代码**，因此无法发现：运行期才构造的调用、依赖具体部署配置的行为、时序与竞态问题。
- **动态派发无法完全解析**：`getattr` 调用、Django 字符串视图引用、框架信号回调等，调用图中不可见。本报告已尽力通过入口提取与字符串搜索补充，但不保证完整。
- **认证/授权状态由静态推断**：报告中标注的鉴权状态来自装饰器与函数体检查，实际生效的鉴权还取决于网关、反向代理与部署配置——这部分**不在代码范围内**，相关结论已标注为需人工确认。
- **依赖组件的已知漏洞**需要 CVE 数据库比对，本轮覆盖情况见 2.1 的 C6 行。

## 三、发现的问题

> 本节列出的是**在第二节所述覆盖范围内**发现的问题。**这不等于**已经审完——某个类别没出现在这里，可能是「审了、没有」，也可能是「根本没审」，两者的区分见 2.1 节。

### 🔴 F-003：XMLRPC delete_all_topic/delete_topic 只校验认证不校验归属，任意注册用户可删除全站主题

| | |
|---|---|
| **位置** | `lib/ylinux_xmlrpc.py:60`（delete_all_topic） |
| **严重度** | CRITICAL |
| **可利用性** | exploitable |
| **类别** | missing_authorization |
| **归因** | project |
| **推理层** | L2 |
| **CWE** | CWE-862 |
| **覆盖类** | C3_认证授权 |
| **验证** | **需人工确认** |

**证据**

- **sink**：lib/ylinux_xmlrpc.py:66 —— Topic.objects.all().delete()（无参数、无过滤条件，删除全部主题）；同文件 52-56 delete_topic 中 topic = Topic.objects.get(pk=id); topic.posts.all().delete(); topic.delete() 同样不检查 topic.user 是否为调用者
- **source**：XMLRPC 方法参数 id/user/passwd（ids 由攻击者任意指定）；凭据可通过自助注册获得（/account/request_register/ 仅需一个可用邮箱接收激活链接，无人工审批）
- **reachability**：settings.py:164-166 XMLRPC_METHODS 暴露 delete_topic/delete_all_topic → urls.py:45-48 (r'^xmlrpc/$', django_xmlrpc.views.handle_xmlrpc) → lib/ylinux_xmlrpc.delete_all_topic/delete_topic；入口清单标注为 required 认证
- **sanitizer_check**：仅有 has_auth()（第 39-45 行 authenticate()）——它只回答「是不是某个有效账号」，不回答「这个账号有没有权限动这条/这些数据」。没有任何 object-level 归属校验、角色校验或管理员判定，delete_all_topic 更是连目标参数都没有。

**攻击路径**

1. 攻击者自助注册并激活一个普通账号
2. 向 /xmlrpc/ 发送 XMLRPC 请求 methodName=delete_all_topic，params 只带自己的用户名/密码
3. 服务端 Topic.objects.all().delete()，全站主题及帖子被清空，无回收站

**数据流**：`XMLRPC 请求 → urls.py:47 handle_xmlrpc → settings.py:166 方法表 → delete_all_topic(user,passwd) → has_auth() 通过 → Topic.objects.all().delete()`

**源码快照**（左侧数字为行号，与上方位置对应）

```python
57 |     except:
   58 |         raise Fault(-1, "delete one topic failed")
   59 | 
   60 | def delete_all_topic(user, passwd):
   61 |     '''delete all topic'''
   62 |     if not has_auth(user, passwd):
   63 |         raise Fault(-1, "***")
   64 | 
   65 |     try:
   66 |         Topic.objects.all().delete()
   67 |         return True
   68 |     except:
   69 |         raise Fault(-1, "delete all topics failed")
   70 | 
   71 | ###
   72 | ### MetaWeblog API
   73 | ###
   74 | def topic_to_struct(topic):
   75 |
```

**对抗验证记录**

- 结论：**需人工确认**
- 验证者推理：验证者未在预算内提交结论。
- 反驳：无法自动核实，需人工复核。
- 独立上下文指纹：`345c1c84b59cc00c`

**修复建议**

delete_all_topic 应要求超级用户权限；delete_topic/edit_topic 应校验 topic.user == 调用者或调用者为管理员。

```
has_auth 改为返回 User 对象，再判断 user.is_superuser；delete_all_topic 直接要求 is_superuser，delete_topic 增加 if topic.user_id != user.id and not user.is_superuser: raise Fault(...)。
```

---

### 🟠 F-001：论坛帖子正文与附件名未净化即标记 |safe，登录用户可注入持久型 XSS

| | |
|---|---|
| **位置** | `app/ydata/models.py:258`（Post.save） |
| **严重度** | HIGH |
| **可利用性** | exploitable |
| **类别** | xss_stored |
| **归因** | project |
| **推理层** | L2 |
| **CWE** | CWE-79 |
| **覆盖类** | C1_注入 |
| **验证** | **需人工确认** |

**证据**

- **sink**：app/ydata/models.py:258-264 —— elif self.markup == 'none': self.body_html = Markdown(extensions=['fenced_code']).convert(ylinux_text_filter(self.body))，随后 self.body_html = urlize(self.body_html)；结果在 app/wiki/utils.py:18 以 {{ post.body_html|safe }} 输出（autoescape 被关闭）
- **source**：Post.body 由登录用户提交（app/ydata/forms.py:46 AddPostForm.save 硬编码 markup='none'，即默认走无 safe_mode 的分支）；Attachment.name 由上传者提交的 multipart 文件名决定（app/ydata/views.py:73/86 name=f.name）
- **reachability**：外部入口 wiki 的 ajax_new_post/add_post（app/wiki/urls.py）或 bbs 回复 → AddPostForm.save()/EditPostForm → Post.save() 写入 body_html → 任何用户打开该主题时 wiki.views → wiki/utils.py render_post() → Template(POST_MAIN).render() 输出 |safe
- **sanitizer_check**：不足：1) 第 260 行 Markdown() 未传 safe_mode='escape'（对比第 256 行 markdown 分支明确用了 safe_mode='escape'），markdown 默认直接放行原始 HTML；2) urlize 只做链接化，不去标签；3) 模板层唯一的防线是 autoescape，被 |safe 显式关闭；4) ylinux_text_filter（models.py:408）用 '<a href="%s">%s</a>' % (a.get_absolute_url(), a.name) 把附件名原样拼进 HTML，形成第二条注入路径。

**攻击路径**

1. 注册/登录任意账号（自助注册：/account/register/<key>/）
2. 在任意主题下回复，正文写 <img src=x onerror=...> 或 <script>...（markup 被表单固定为 none）
3. Post.save() 原样存入 body_html
4. 任何用户/管理员浏览该主题即在其浏览器上下文执行脚本（可读取会话、以受害者身份发请求）

**数据流**：`request.POST['body'] → AddPostForm.save() → Post(body=...) → Post.save() models.py:260 → body_html → 模板 |safe wiki/utils.py:18`

**源码快照**（左侧数字为行号，与上方位置对应）

```python
255 |         elif self.markup == 'markdown':
  256 |             self.body_html = unicode(Markdown(self.body, safe_mode='escape'))
  257 |             #self.body_html = markdown(self.body, 'safe')
  258 |         elif self.markup == 'none':
  259 |             #self.body_html = self.body
  260 |             self.body_html = Markdown(extensions=['fenced_code']).convert(ylinux_text_filter(self.body))
  261 |         else:
  262 |             raise Exception('Invalid markup property: %s' % self.markup)
  263 |         #self.body_text = strip_tags(self.body_html)
  264 |         self.body_html = urlize(self.body_html)
  265 |         if ydata_settings.SMILES_SUPPORT:
  266 |             self.body_html = smiles(self.body_html)
  267 | 
  268 |         if not self.updated:
  269 |             self.updated = datetime.datetime.now()
  270 |
```

**对抗验证记录**

- 结论：**需人工确认**
- 验证者推理：验证者未在预算内提交结论。
- 反驳：无法自动核实，需人工复核。
- 独立上下文指纹：`79ad75844ad3f646`

**修复建议**

统一走 safe_mode='escape' 或使用白名单 sanitizer（如 bleach）后再标记 safe；模板中去掉 |safe，附件名用 escape()/模板变量输出。

```
models.py:260 改为 Markdown(extensions=['fenced_code'], safe_mode='escape')；models.py:408 的 %s 用 django.utils.html.escape(a.name) 包裹；对 markup='none' 分支同样处理。
```

---

### 🟠 F-002：无鉴权入口 /lab/update_post_profile 全表改写所有帖子的 touser/updated 字段

| | |
|---|---|
| **位置** | `app/ylab/views.py:37`（update_post_profile） |
| **严重度** | HIGH |
| **可利用性** | exploitable |
| **类别** | missing_authorization |
| **归因** | project |
| **推理层** | L2 |
| **CWE** | CWE-862 |
| **覆盖类** | C3_认证授权 |
| **验证** | **需人工确认** |

**证据**

- **sink**：app/ylab/views.py:39-46 —— posts = Post.objects.all(); for p in posts: ... p.updated = p.created; p.save()（逐个 UPDATE 整张帖子表）
- **source**：无需任何请求参数；触发条件是 URL 本身。app/ylab/urls.py:8 将 ^update_post_profile$ 直接映射到该视图，外部入口清单把它标为无鉴权。
- **reachability**：GET /lab/update_post_profile → urls.py:31 (r'^lab/', include(ylinux.app.ylab.urls)) → app/ylab/urls.py:8 → app/ylab/views.py:37 update_post_profile
- **sanitizer_check**：无。视图上没有 login_required/permission_required 装饰器（文件第 9 行虽然 import 了它们却未在此使用），也没有 request.method 判断或任何 token 校验。

**攻击路径**

1. 攻击者（无需登录、无需 Cookie）直接请求 GET /lab/update_post_profile
2. 服务端遍历全站 Post 行，把 updated 重置为 created、按 parent/topic 重算 touser
3. 全站帖子的时间排序/更新标记被抹平，站内通知对象被改写；可反复触发形成持续篡改

**数据流**：`外部 GET /lab/update_post_profile → urls.py:31 → ylab/urls.py:8 → update_post_profile() → Post.objects.all() → p.save()`

**源码快照**（左侧数字为行号，与上方位置对应）

```python
34 |     return HttpResponse(r)
   35 | 
   36 | 
   37 | def update_post_profile(req):
   38 |     
   39 |     posts = Post.objects.all()
   40 |     for p in posts:
   41 |         if p.parent:
   42 |             p.touser = p.parent.user
   43 |         else:
   44 |             p.touser = p.topic.user
   45 |         p.updated = p.created
   46 |         p.save()
   47 | 
   48 |     return HttpResponse(u'更新 posts 完成!')
```

**对抗验证记录**

- 结论：**需人工确认**
- 验证者推理：验证者未在预算内提交结论。
- 反驳：无法自动核实，需人工复核。
- 独立上下文指纹：`5b9457d4e335035c`

**修复建议**

该视图是一次性运维脚本，应删除或加 management command 化，不得挂在公开 URL 上；如必须保留，加 @login_required + @permission_required('admin')。

```
app/ylab/urls.py 删除 update_post_profile 路由；或视图首行加 if not req.user.is_staff: return HttpResponseForbidden()。
```

---

### 🟡 F-009：全局无 CSRF 防护，管理端删除/重启等破坏性操作绑定在 GET 上，登录管理员可被跨站诱导删数据

| | |
|---|---|
| **位置** | `app/admin/views.py:134`（del_permission / del_group / del_user / del_catalog / reboot） |
| **严重度** | MEDIUM |
| **可利用性** | exploitable |
| **类别** | csrf |
| **归因** | project |
| **推理层** | L2 |
| **CWE** | CWE-352 |
| **覆盖类** | C3_认证授权 |
| **验证** | 未经对抗验证 |

**证据**

- **sink**：app/admin/views.py:131-134（del_permission）、182-192、246-257、343-354 —— 先 get_object_or_404(...).delete()，然后 HttpResponseRedirect；副作用操作绑定在 GET 上且无任何 CSRF token 校验
- **source**：跨站发起的 HTTP GET 请求（浏览器自动携带会话 Cookie），无 token 参数可控性要求
- **reachability**：带 Cookie 的跨站 GET 即可命中（app/admin/urls.py:16/24/33/41 → ^user/(?P<id>\d+)/del$ 等）；无需用户交互以外的任何条件，Cookie 默认按域发送，同站 Cookie 无法因 SameSite 机制阻断（本项目未使用现代 SameSite 设置）
- **sanitizer_check**：无。工程内全局搜索未发现 csrf_token 模板标签使用、未发现 @csrf_protect、settings 里没有任何 CSRF 中间件，删除操作也不要求 POST，因此浏览器跨站 <img>/<script> 请求即可完成。

**攻击路径**

1. 攻击者把自己的页面发给已登录的管理员（论坛私信/邮件/外部站点）
2. 页面包含 <img src="http://site/admin/user/3/del"> 或 -- 注意 URL 前缀为站点真实部署前缀 -- 多个 <img> 标签
3. 管理员浏览器自动带上 Cookie 发起 GET
4. 视图无 CSRF token 校验 → user/group/permission/catalog 被逐个删除，权限体系被破坏

**数据流**：`跨站 GET 请求（带 Cookie）→ 自定义 SessionMiddleware 恢复 request.user → AuthenticationMiddleware 填 request.user → permission_required('***') 判定通过 → User.objects.get(pk=id).delete() → HttpResponseRedirect(HTTP_REFERER)`

**已存在的缓解措施**（影响严重度判定）

- @permission_required('account.delete_user') 等权限装饰器 —— 只校验权限、不区分请求是否来自本站页面，不能防 CSRF
- settings.py:98-104 的 MIDDLEWARE_CLASSES 中没有 CsrfViewMiddleware / CsrfMiddleware，因此连 POST 表单也没有 token 校验

**源码快照**（左侧数字为行号，与上方位置对应）

```python
131 |     permission = get_object_or_404 (Permission, pk=id)
  132 |     # 这里等待以后验证是否已有其他关联
  133 |     permission.delete()
  134 |     return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
  135 | 
  136 | 
  137 | # Group 管理
  138 | # show, add, edit, del
  139 | 
  140 | @permission_required('account.view_group')
```

**修复建议**

所有破坏性操作改为仅接受带 CSRF token 的 POST，并启用 Django 的 CSRF 中间件。

```
删除/重启类视图改 @require_POST + 模板加 {% csrf_token %}，并在 MIDDLEWARE_CLASSES 加入 django.middleware.csrf.CsrfViewMiddleware（注意 Django 版本兼容）；reboot 加二次确认。
```

---

### 🟡 F-004：附件下载接口无鉴权，枚举自增 id 可拖走全站上传文件

| | |
|---|---|
| **位置** | `app/ydata/views.py:117`（download_attachment） |
| **严重度** | MEDIUM |
| **可利用性** | exploitable |
| **类别** | missing_authorization |
| **归因** | project |
| **推理层** | L2 |
| **CWE** | CWE-284 |
| **覆盖类** | C3_认证授权 |
| **验证** | 未经对抗验证 |

**证据**

- **sink**：app/ydata/views.py:125-126 —— f = open(a.get_absolute_path()); response = HttpResponse(f.read())：无鉴权地读取并返回任意附件实体内容
- **source**：URL 中的 id（?P<id>\d+），外部完全可控且可枚举；Attachment.pk 为自增整数，无不可猜测前缀（见 app/ydata/views.py:73/86 上传时未设随机名）
- **reachability**：外部入口 app/ydata/urls.py:9 ^attachment/(?P<id>\d+)/download/$（入口清单标为无鉴权）→ urls.py:30 (r'^ydata/', include(...)) → app/ydata/views.py:117 download_attachment
- **sanitizer_check**：无。同一文件里 upload_single_file（第 31 行）和 remove_attachment（第 109 行）都标了 @login_required，download_attachment 和 show_attachment（第 101 行）都没有任何装饰器，也没有 owner 校验（Attachment.user 字段存在却不比对）。

**攻击路径**

1. 无需登录，直接 GET /ydata/attachment/1/download/
2. id 换成任意数字（附件表主键连续）
3. 服务端 open(a.get_absolute_path()) 读文件并整文件回显（含 Content-Disposition 原始文件名）
4. 逐个递增 id 即可拖走全站上传附件（论坛/维基中的私有文档、图片）

**数据流**：`GET /ydata/attachment/<id>/download/ → ydata/urls.py:9 → download_attachment(request, id) → Attachment.objects.get(pk=id) → open(a.get_absolute_path()).read() → HttpResponse`

**已存在的缓解措施**（影响严重度判定）

- get_object_or_404 仅保证对象存在，不做归属/权限判断

**源码快照**（左侧数字为行号，与上方位置对应）

```python
114 |     return {'attachment': a}
  115 | 
  116 | 
  117 | def download_attachment(request, id):
  118 | 
  119 |     a = get_object_or_404(Attachment,pk=id)
  120 | 
  121 |     a.dtimes += 1
  122 |     a.save()
  123 | 
  124 |     print a.get_absolute_path()
  125 |     f = open(a.get_absolute_path())
  126 |     response = HttpResponse(f.read())
  127 |     f.close()
  128 | 
  129 |     type, encoding = mimetypes.guess_type(a.get_absolute_path())
  130 |     if type is None:
  131 |         type = 'application/octet-stream'
  132 |     response['Content-Type'] = type
  133 |     response['Content-Length'] = str(a.size)
  134 |     if encoding is not None:
  135 |         response['Content-Encoding'] = encoding
  136 | 
  137 |     # To inspect details for the below code, see http://greenbytes.de/tech/tc2231/
```

**修复建议**

附件下载需鉴权并校验归属；如需公开分享，应引入不可枚举的 token 而非自增 id。

```
给 download_attachment/show_attachment 加 @login_required，并在函数体开头校验 a.user == req.user or req.user.has_perm('ydata.view_attachment')；对完全公开的附件另建白名单逻辑。
```

---

### 🟡 F-010：附件上传直接用客户端文件名拼本地路径落盘，未做 basename/规范化（登录用户可路径穿越写文件）

| | |
|---|---|
| **位置** | `app/ydata/views.py:78`（upload_single_file） |
| **严重度** | MEDIUM |
| **可利用性** | conditional |
| **类别** | path_traversal |
| **归因** | project |
| **推理层** | L2 |
| **CWE** | CWE-22 |
| **覆盖类** | C5_文件路径 |
| **验证** | 未经对抗验证 |

**证据**

- **sink**：app/ydata/views.py:78-84 —— local_name = str(id) + '-' + str(req.user.id) + '-' + f.name；save_path = os.path.join(settings.MEDIA_ROOT, ydata_settings.ATTACHMENT_UPLOAD_TO, local_name)；save_file = open(save_path, 'wb+')；for chunk in f.chunks(): save_file.write(chunk)
- **source**：multipart 上传文件名 f.name（客户端 Content-Disposition filename），外部完全可控；要求登录（上传视图绑定 req.user）
- **reachability**：入口 app/ydata/urls.py:6 ^uploadsf/(?P<id>\d+)/$ → ydata.views.upload_single_file（视图使用 req.user.id 创建 Attachment，属登录后入口，非匿名可达）；同型代码在无鉴权的 app/ylab/urls.py:7 也存在但那里只返回提示、不落盘
- **sanitizer_check**：无。代码中没有任何 os.path.basename、django.utils.text.get_valid_filename 或路径规范化检查，也未使用经过校验的 FileSystemStorage.save。

**攻击路径**

1. 以登录用户身份 POST 到 /ydata/uploadsf/<id>/（multipart），把 single_file 的 filename 设为 ../../../../templates/x.html
2. 服务端用该 filename 拼出本地路径并 open(...,'wb+') 写入
3. 文件被写到 MEDIA_ROOT/上传目录之外（如模板目录），可覆盖模板/静态文件或写入同用户可写目录，造成内容篡改（虽不是直接代码执行，但可变成持久 XSS/页面篡改）

**数据流**：`multipart filename (f.name) → local_name = str(id)+'-'+str(req.user.id)+'-'+f.name → os.path.join(settings.MEDIA_ROOT, ATTACHMENT_UPLOAD_TO, local_name) → open(save_path,'wb+') → 写入磁盘`

**已存在的缓解措施**（影响严重度判定）

- 文件名前缀拼接了 str(id) 与 str(req.user.id)，但这段前缀不能阻断 '../' 序列
- f.name 经 Django multipart 解析器取得，是否已做 basename/suspicious-path 处理取决于 Django 版本（本项无从静态确认，见 limitations）

**源码快照**（左侧数字为行号，与上方位置对应）

```python
75 |                 attachment.topic = topic
   76 | 
   77 |     else:
   78 |         local_name = str(id) + '-' + str(req.user.id) + '-' + f.name
   79 |         save_path = os.path.join(settings.MEDIA_ROOT,
   80 |                                  ydata_settings.ATTACHMENT_UPLOAD_TO,
   81 |                                  local_name)
   82 |         save_file = open(save_path, 'wb+')
   83 |         for chunk in f.chunks():
   84 |             save_file.write(chunk)
   85 | 
   86 |         attachment = Attachment(user=req.user, name=f.name, path=local_name, size=f.size, hash=fhash)
   87 |         if topic:
   88 |             attachment.topic = topic
   89 | 
   90 |     attachment.save()
```

**修复建议**

入库文件名必须取 basename 并做白名单字符校验，落盘路径要校验规范化后仍在允许目录内。

```
name = os.path.basename(f.name) 后再做 get_valid_filename；写入前 os.path.realpath 并断言仍在上传目录内；或改用 django.core.files.storage.default_storage.save()。
```

---

### 🟡 F-005：上传响应把客户端文件名原样拼进 <script> 块，无鉴权上传入口可反射 XSS

| | |
|---|---|
| **位置** | `app/ylab/views.py:33`（upload_single_file） |
| **严重度** | MEDIUM |
| **可利用性** | exploitable |
| **类别** | reflected_xss |
| **归因** | project |
| **推理层** | L2 |
| **CWE** | CWE-79 |
| **覆盖类** | C1_注入 |
| **验证** | 未经对抗验证 |

**证据**

- **sink**：app/ylab/views.py:33 —— r = u'<script type="text/javascript">window.parent.AfterSubmit(%s);</script>' % innerHTML，而 innerHTML 在第 32 行由 attachment.name（客户端文件名）拼接而成，通过 HttpResponse(r) 原样返回
- **source**：multipart 请求里上传文件的 Content-Disposition filename（req.FILES.values()[0].name），外部完全可控
- **reachability**：无鉴权外部入口 app/ylab/urls.py:7 → ylab.views.upload_single_file（视图体内无任何鉴权装饰器/检查，仅判断 req.method != 'POST'）；入口分类器把该行标为未分类，但代码本身没有认证控制
- **sanitizer_check**：无。attachment.name（客户端 filename）未经过 escape()/urlquote()/CSP，直接进入 <script> 块；只要 filename 含 '</script>' 即可提前结束脚本块，后续内容作为 HTML 执行（与拼进去的 JS 是否语法正确无关）。

**攻击路径**

1. 构造 multipart POST 到 /lab/uploadsf，single_file 字段的 filename 含 </script><script>alert(document.cookie)</script>
2. 服务端把 filename 原样拼进 <script>...</script> 响应体
3. 浏览器解析到 </script>，后续内容作为 HTML 执行 → 任意 JS 在受害者会话中执行

**数据流**：`multipart filename → req.FILES.values()[0] (ylab/views.py:31) → attachment.name → innerHTML (第 32 行) → <script> 字符串拼接 (第 33 行) → 未转义的 HTML 响应`

**已存在的缓解措施**（影响严重度判定）

- 无。响应未经过 template 渲染，因此 Django 自动转义不起作用

**源码快照**（左侧数字为行号，与上方位置对应）

```python
30 |     url = '/ydata/attachement/3'
   31 |     attachment = req.FILES.values()[0]
   32 |     innerHTML = u'<span><a href="%s">%s</a>， %s， <a href="%s/delete">删除</a></span>' % (url, attachment.name, attachment.size, url)
   33 |     r = u'<script type="text/javascript">window.parent.AfterSubmit(%s);</script>' % innerHTML
   34 |     return HttpResponse(r)
   35 | 
   36 | 
   37 | def update_post_profile(req):
   38 |     
   39 |     posts = Post.objects.all()
   40 |     for p in posts:
```

**修复建议**

文件名等外部数据在写入 HTML/JS 前必须转义（escape + JSON 序列化），或用 template + ajax 返回值代替拼 HTML。

```
用 django.utils.html.escape / json.dumps 生成 JS 字符串字面量，不要手拼 <script>；同型代码 ydata/views.py:91-95 一并修。
```

---

### 🟡 F-008：settings.py 硬编码 SECRET_KEY 与数据库口令（'***'）

| | |
|---|---|
| **位置** | `settings.py:79`（module-level settings） |
| **严重度** | MEDIUM |
| **可利用性** | conditional |
| **类别** | hardcoded_secret |
| **归因** | project |
| **推理层** | L2 |
| **CWE** | CWE-798 |
| **覆盖类** | C4_凭据配置 |
| **验证** | 未经对抗验证 |

**证据**

- **sink**：settings.py:79 —— <assigned_secret:<50*** len=10 fp=0e***be6>（secret 引擎 django_secret_key 命中）；settings.py:49 —— '***': '***' 硬编码在 DATABASES 中
- **source**：仓库内的字面量（提交历史可见），非外部输入；属配置/凭据管理缺陷
- **reachability**：settings.py 被 manage.py:…（DJANGO_SETTINGS_MODULE=settings）加载，任何请求都会使用该 SECRET_KEY；数据库口令在建立连接时使用
- **sanitizer_check**：无。仓库内未见任何从环境变量/外部密钥文件读取这两个值的分支，也没有 local_settings 导入机制。

**攻击路径**

1. 任何拿到源码/仓库的人（或曾经泄露的副本）直接获得 SECRET_KEY 与数据库口令
2. 若线上部署未覆盖这两个值：用 SECRET_KEY 伪造/篡改签名数据（session cookie、password reset token 类数据）；用 DB 口令直连数据库（前提是端口可达、口令未被改）
3. 弱口令 '***' 也极易被暴力猜解

**数据流**：`仓库中静态字面量 → settings.SECRET_KEY / DATABASES['***']['***'] → Django 签名/会话机制 与 DB 连接`

**已存在的缓解措施**（影响严重度判定）

- settings.py:29-32 的邮件凭据为空白，说明已部分做了脱敏处理；SECRET_KEY/DB 口令未被同样处理
- 线上是否用环境变量覆盖本文件无法从静态代码判断（见 limitations）

**源码快照**（左侧数字为行号，与上方位置对应）

```python
76 | 
   77 | 
   78 | # Make this unique, and don't share it with anybody.
   79 | <assigned_secret:c#0*** len=50 fp=f5038eced716>
   80 | 
   81 | 
   82 | # YLinux 后端认证模块，这是一个tuple，可以有多种后段认证技术，
   83 | # 只要有一个成功即可。详细说明请看 ylinux.app.accout 
   84 | AUTHENTICATION_BACKENDS = ('***',)
   85 | LOGIN_URL = '/account/login/'
```

**修复建议**

密钥与数据库口令改为从环境变量/外部配置文件注入，仓库中只保留占位符；已泄露的 key 与口令应立即轮换。

```
SECRET_KEY = os.environ['***']；数据库口令改从环境/local_settings.py 读取并加入 .gitignore；轮换已泄露的 key 与 DB 口令。
```

---

### 🔵 F-006：口令盐与激活 key 使用非密码学 PRNG（random.random）且盐仅 5 位十六进制

| | |
|---|---|
| **位置** | `app/account/models.py:232`（User.set_password / RegisterManager.create_profile / User.reset_activation_key / UserManager.make_random_password） |
| **严重度** | LOW |
| **可利用性** | conditional |
| **类别** | weak_crypto |
| **归因** | project |
| **推理层** | L2 |
| **CWE** | CWE-338 |
| **覆盖类** | C4_凭据配置 |
| **验证** | 未经对抗验证 |

**证据**

- **sink**：app/account/models.py:232/364/427 —— salt = get_hexdigest(algo, str(random.random()), …)[:5] / sha_constructor(str(random.random())).hexdigest()[:5]，用非密码学 PRNG 派生口令盐与激活 key；第 143-148 行 make_random_password 同样用 random.choice
- **source**：服务器本地 PRNG 输出（非外部输入），但生成的是认证凭据材料（激活 key / 临时口令），属凭据生成缺陷
- **reachability**：无鉴权入口 app/account/urls.py:7 ^register/$（申请注册、生成 key）与 app/account/urls.py:8 ^register/(?P<key>.+)/$（使用 key）→ app/account/views.py → account.models.RegisterManager.create_profile/reset_activation_key
- **sanitizer_check**：无。全文件搜索未出现 os.urandom / secrets / hashlib.sha256 等安全随机源，盐与一次性口令均取自 random 模块（models.py:147-148、232、364、427）。

**攻击路径**

1. 注册/找回密码时服务端用 random.random() 生成 activation_key 的盐
2. Python2 的 random 为 MT19937，观测同一进程若干输出即可重构状态并预测后续输出
3. 若能预测盐（或直接命中 5 位十六进制盐空间），可为任意 email 伪造激活/重置链接

**数据流**：`request (email) → RegisterManager.create_profile / User.reset_activation_key → random.random() 盐 → sha1(salt+email) → activation_key → 邮件 URL /account/register/<key>/`

**已存在的缓解措施**（影响严重度判定）

- activation_key 需通过 SHA1_RE 格式校验才被接受（models.py:374），但那只限制格式不限制可预测性

**源码快照**（左侧数字为行号，与上方位置对应）

```python
229 |         "***"
  230 |         import random
  231 |         algo = 'sha1'
  232 |         salt = get_hexdigest(algo, str(random.random()), str(random.random()))[:5]
  233 |         hsh = get_hexdigest(algo, salt, raw_password)
  234 |         self.password = '***' % (algo, salt, hsh)
  235 | 
  236 |     def check_password(self, raw_password):
  237 |         """
  238 |         Returns a boolean of whether the raw_password was correct. Handles
  239 |         encryption formats behind the scenes.
  240 |         """
  241 |         # Backwards-compatibility check. Older passwords won't include the
  242 |         # algorithm or salt.
  243 |         if '$' not in self.password:
  244 |             is_correct = (self.password == get_hexdigest('md5', '', raw_password))
  245 |             if is_correct:
  246 |                 # Convert the password to the new, more secure format.
  247 |                 self.set_password(raw_password)
  248 |                 self.save()
  249 |             return is_correct
  250 |         return check_password(raw_password, self.password)
  251 | 
  252 |     def set_unusable_password(self):
```

**修复建议**

口令盐与一次性令牌必须来自 os.urandom/secrets，且口令存储改用带迭代次数的 KDF（pbkdf2/bcrypt）；盐长度不应只有 5 个十六进制字符。

```
from os import urandom；salt = binascii.hexlify(urandom(8))；口令改用 hashlib.pbkdf2_hmac 或 bcrypt/加装 django.contrib.auth.hashers。
```

---

### 🔵 F-007：多处重定向目标取自 HTTP_REFERER / ?next= 且未校验，构成开放重定向（含登录后与登出跳转）

| | |
|---|---|
| **位置** | `app/admin/views.py:134`（del_permission / del_group / del_user / del_catalog / login） |
| **严重度** | LOW |
| **可利用性** | exploitable |
| **类别** | open_redirect |
| **归因** | project |
| **推理层** | L2 |
| **CWE** | CWE-601 |
| **覆盖类** | C1_注入 |
| **验证** | 未经对抗验证 |

**证据**

- **sink**：app/admin/views.py:134/192/257/354 —— return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))；app/admin/views.py:62 与 app/account/views.py:38 —— HttpResponseRedirect(request.session.get('previous_url'|'login_redirect_url','/'))，其 session 值分别在第 65 行（HTTP_REFERER）与第 44 行（?next=）写入；app/account/views.py:58-60 的 logout 同样取 request.GET['next']
- **source**：HTTP_REFERER 请求头 / ?next= 查询参数，外部完全可控
- **reachability**：无鉴权入口 app/account/urls.py:10 ^logout/$（logout 视图直接 HttpResponseRedirect(previous_url or '/')，任何匿名请求可触发）；app/account/urls.py:9 ^login/$ 与 app/admin/urls.py:8 ^login/$ 提供 session 变量的来源
- **sanitizer_check**：无。全处只做 `or '/'` 的空值回退，没有 host 白名单/is_safe_url/相对路径限制，因此 http://evil.com 会原样进入 Location 头。

**攻击路径**

1. 攻击者在自己的页面放链接/表单 → 管理员点击（或登录成功后自动跳转）
2. 请求带上 Referer: http://evil.com 或 ?next=http://evil.com
3. 服务端把该值写入 session 并用作 HttpResponseRedirect 目标
4. 浏览器 302 到攻击者站点（可用于钓鱼、配合 OAuth/凭据窃取）

**数据流**：`请求头 Referer → request.META['HTTP_REFERER'] → (admin) request.session['previous_url'] / 直接 HttpResponseRedirect → Location: evil.com → ?next= → request.GET.get('next') → session['login_redirect_url'] / previous_url → HttpResponseRedirect`

**已存在的缓解措施**（影响严重度判定）

- 有默认值 '/'（仅在取不到时生效），无 origin/host 白名单校验，未使用 django.utils.http.is_safe_url 之类的校验

**源码快照**（左侧数字为行号，与上方位置对应）

```python
131 |     permission = get_object_or_404 (Permission, pk=id)
  132 |     # 这里等待以后验证是否已有其他关联
  133 |     permission.delete()
  134 |     return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
  135 | 
  136 | 
  137 | # Group 管理
  138 | # show, add, edit, del
  139 | 
  140 | @permission_required('account.view_group')
```

**修复建议**

重定向目标必须校验为站内相对路径（白名单 host 或强制 / 开头），不要直接使用 HTTP_REFERER 或 ?next=。

```
引入一个 safe_redirect(target) 帮助函数：仅当 target 以 '/' 开头且不含 '//'、或 host 在 ALLOWED_HOSTS 内才跳转，否则回 '/'；登录 next 走同一校验。
```

---

### 🔵 F-011：ylab 模块保留未完成的脚手架/占位代码（硬编码附件 URL、'Just for POST test!' 调试文案、指向不存在路径的删除链接）并对外可达

| | |
|---|---|
| **位置** | `app/ylab/views.py:30`（upload_single_file（模块级占位/脚手架）） |
| **严重度** | LOW |
| **可利用性** | not_exploitable |
| **类别** | insecure_placeholder_code |
| **归因** | project |
| **推理层** | L2 |
| **覆盖类** | C7_AI代码特有 |
| **验证** | 未经对抗验证 |

**证据**

- **sink**：app/ylab/views.py:30 url = '/ydata/attachement/3'（硬编码不存在的附件 id，且 'attachement' 拼写与真实路由 'attachment' 不一致）；app/ylab/views.py:31 上方提示文案 'Just for POST test!'；app/ylab/views.py:32 生成指向 '%s/delete' 的删除链接，而真实删除路由是 ydata:delete_attachment（^attachment/(?P<id>\d+)/remove/$），链接必然 404；app/ylab/views.py:17 的 time() 用 print 输出 `%s` 占位（非视图，仍被 import 执行）
- **source**：代码内的硬编码占位常量（无外部输入）
- **reachability**：app/ylab/urls.py:6/7/8 三个路由全部可达
- **sanitizer_check**：无（不适用：问题在于未经实现与审查的占位代码被部署）

**攻击路径**

1. 无需攻击者：功能本身从未完成，提示/链接指向不存在的地址，用户点击即失败
2. 同时该占位视图所在的模块与 F-002 的无鉴权全表改写共存，说明该 app 没有被上线前审查，整体风险被低估

**数据流**：`无外部数据流；缺陷在于代码状态而非输入处理`

**已存在的缓解措施**（影响严重度判定）

- 无

**源码快照**（左侧数字为行号，与上方位置对应）

```python
27 |     if req.method != 'POST':
   28 |         return HttpResponse("Just for POST test!")
   29 | 
   30 |     url = '/ydata/attachement/3'
   31 |     attachment = req.FILES.values()[0]
   32 |     innerHTML = u'<span><a href="%s">%s</a>， %s， <a href="%s/delete">删除</a></span>' % (url, attachment.name, attachment.size, url)
   33 |     r = u'<script type="text/javascript">window.parent.AfterSubmit(%s);</script>' % innerHTML
   34 |     return HttpResponse(r)
   35 | 
   36 | 
   37 | def update_post_profile(req):
   38 |     
   39 |     posts = Post.objects.all()
   40 |     for p in posts:
   41 |         if p.parent:
   42 |             p.touser = p.parent.user
   43 |         else:
   44 |             p.touser = p.topic.user
   45 |         p.updated = p.created
   46 |         p.save()
   47 | 
   48 |     return HttpResponse(u'更新 posts 完成!')
```

**修复建议**

下线未完成的脚手架代码（或补全并使用 reverse() 生成链接）；对 app/ylab 整体做一次上线前审查。

```
删除 app/ylab 或补全实现（正确路由用 reverse('ydata:delete_attachment')），并在 CI 中加入“占位常量/调试字符串”检查。
```

---

## 四、候选处置台账

两条来源的候选都必须有处置结论。**保留驳回理由**是本节的重点——驳回一个真实的漏洞与忽略它是两回事，理由让后者可以被复核。

### 4.1 静态引擎候选

共 34 条：confirmed 18、dismissed 16

| 候选 | 引擎 | 规则 | 位置 | 严重度 | 处置 | 理由 |
|---|---|---|---|---|---|---|
| C0001 | semgrep | python.django.security.injection.open-redirect.open-redirect | `app/admin/views.py:62` | MEDIUM | ✅确认 | 命中：admin/views.py:62/134/192/257/354 的重定向目标分别来自 request.session['previous_url']（其值在第 65 行由 request.META['HTTP_REFERER'] 写入）与直接取 request.META.get('HTTP_REFERER', |
| C0002 | semgrep | python.django.security.injection.open-redirect.open-redirect | `app/admin/views.py:62` | MEDIUM | ✅确认 | 命中：admin/views.py:62/134/192/257/354 的重定向目标分别来自 request.session['previous_url']（其值在第 65 行由 request.META['HTTP_REFERER'] 写入）与直接取 request.META.get('HTTP_REFERER', |
| C0003 | semgrep | python.django.security.injection.open-redirect.open-redirect | `app/admin/views.py:134` | MEDIUM | ✅确认 | 命中：admin/views.py:62/134/192/257/354 的重定向目标分别来自 request.session['previous_url']（其值在第 65 行由 request.META['HTTP_REFERER'] 写入）与直接取 request.META.get('HTTP_REFERER', |
| C0004 | semgrep | python.django.security.injection.open-redirect.open-redirect | `app/admin/views.py:134` | MEDIUM | ✅确认 | 命中：admin/views.py:62/134/192/257/354 的重定向目标分别来自 request.session['previous_url']（其值在第 65 行由 request.META['HTTP_REFERER'] 写入）与直接取 request.META.get('HTTP_REFERER', |
| C0005 | semgrep | python.django.security.injection.open-redirect.open-redirect | `app/admin/views.py:192` | MEDIUM | ✅确认 | 命中：admin/views.py:62/134/192/257/354 的重定向目标分别来自 request.session['previous_url']（其值在第 65 行由 request.META['HTTP_REFERER'] 写入）与直接取 request.META.get('HTTP_REFERER', |
| C0006 | semgrep | python.django.security.injection.open-redirect.open-redirect | `app/admin/views.py:192` | MEDIUM | ✅确认 | 命中：admin/views.py:62/134/192/257/354 的重定向目标分别来自 request.session['previous_url']（其值在第 65 行由 request.META['HTTP_REFERER'] 写入）与直接取 request.META.get('HTTP_REFERER', |
| C0007 | semgrep | python.django.security.injection.open-redirect.open-redirect | `app/admin/views.py:257` | MEDIUM | ✅确认 | 命中：admin/views.py:62/134/192/257/354 的重定向目标分别来自 request.session['previous_url']（其值在第 65 行由 request.META['HTTP_REFERER'] 写入）与直接取 request.META.get('HTTP_REFERER', |
| C0008 | semgrep | python.django.security.injection.open-redirect.open-redirect | `app/admin/views.py:257` | MEDIUM | ✅确认 | 命中：admin/views.py:62/134/192/257/354 的重定向目标分别来自 request.session['previous_url']（其值在第 65 行由 request.META['HTTP_REFERER'] 写入）与直接取 request.META.get('HTTP_REFERER', |
| C0009 | semgrep | python.django.security.injection.open-redirect.open-redirect | `app/admin/views.py:354` | MEDIUM | ✅确认 | 命中：admin/views.py:62/134/192/257/354 的重定向目标分别来自 request.session['previous_url']（其值在第 65 行由 request.META['HTTP_REFERER'] 写入）与直接取 request.META.get('HTTP_REFERER', |
| C0010 | semgrep | python.django.security.injection.open-redirect.open-redirect | `app/admin/views.py:354` | MEDIUM | ✅确认 | 命中：admin/views.py:62/134/192/257/354 的重定向目标分别来自 request.session['previous_url']（其值在第 65 行由 request.META['HTTP_REFERER'] 写入）与直接取 request.META.get('HTTP_REFERER', |
| C0011 | semgrep | python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1 | `app/ydata/views.py:52` | MEDIUM | ❌驳回 | 驳回：ydata/views.py:52-55 的 sha1 用于对上传文件内容做去重摘要（hashlib.sha1 循环 update(f.chunks()) 后存为 Attachment.hash，再 filter(hash=...) 查重），不涉及口令存储或签名，SHA1 碰撞在此场景不产生安全后果。 |
| C0012 | bandit | B608 | `app/account/backends.py:43` | MEDIUM | ❌驳回 | 驳回：account/backends.py:42-57 用 % 拼进 SQL 的每一项都是常量字符串并经 connection.ops.quote_name（qn()）引用为标识符；唯一动态值 user_obj.id 由 %%s 占位符绑定在 cursor.execute(sql, [user_obj.id]) 参数 |
| C0013 | bandit | B101 | `app/account/middleware.py:19` | LOW | ❌驳回 | 驳回：两处 assert 均为内部不变式检查（account/middleware.py:19 在会话恢复后断言，lib/markdown/html4.py:184 在库内部），不是鉴权判定；Python -O 只会在主流程去掉断言，不会绕过任何权限检查（真正的鉴权缺失已在 F-003 记录）。 |
| C0014 | bandit | B105 | `app/account/models.py:44` | LOW | ❌驳回 | 驳回：三处命中均为 B105 字符串误报——account/models.py:44 的 '!'***'True' 是模板标记 PASSWORD_RESET_DONE，settings.py:32 的 EMAIL_HOST_PAS |
| C0015 | bandit | B311 | `app/account/models.py:148` | LOW | ✅确认 | 命中：account/models.py:147-148/232/364/427 用 random.choice / random.random 生成临时口令、口令盐与激活 key，已合并记录为 F-006。 |
| C0016 | bandit | B311 | `app/account/models.py:232` | LOW | ✅确认 | 命中：account/models.py:147-148/232/364/427 用 random.choice / random.random 生成临时口令、口令盐与激活 key，已合并记录为 F-006。 |
| C0017 | bandit | B311 | `app/account/models.py:232` | LOW | ✅确认 | 命中：account/models.py:147-148/232/364/427 用 random.choice / random.random 生成临时口令、口令盐与激活 key，已合并记录为 F-006。 |
| C0018 | bandit | B311 | `app/account/models.py:364` | LOW | ✅确认 | 命中：account/models.py:147-148/232/364/427 用 random.choice / random.random 生成临时口令、口令盐与激活 key，已合并记录为 F-006。 |
| C0019 | bandit | B311 | `app/account/models.py:427` | LOW | ✅确认 | 命中：account/models.py:147-148/232/364/427 用 random.choice / random.random 生成临时口令、口令盐与激活 key，已合并记录为 F-006。 |
| C0020 | bandit | B105 | `app/account/views.py:221` | LOW | ❌驳回 | 驳回：三处命中均为 B105 字符串误报——account/models.py:44 的 '!'***'True' 是模板标记 PASSWORD_RESET_DONE，settings.py:32 的 EMAIL_HOST_PAS |
| C0021 | bandit | B605 | `app/admin/views.py:362` | LOW | ❌驳回 | 驳回：admin/views.py:362-363 的 shell 命令是 'killall -u %s' % user，而 user 来自同模块 os.popen('whoami') 的输出（服务进程自身用户名），没有外部可控数据进入命令串，不构成命令注入；B607 的部分路径执行在当前调用方式下无实际影响。该处真正 |
| C0022 | bandit | B607 | `app/admin/views.py:362` | LOW | ❌驳回 | 驳回：admin/views.py:362-363 的 shell 命令是 'killall -u %s' % user，而 user 来自同模块 os.popen('whoami') 的输出（服务进程自身用户名），没有外部可控数据进入命令串，不构成命令注入；B607 的部分路径执行在当前调用方式下无实际影响。该处真正 |
| C0023 | bandit | B605 | `app/admin/views.py:363` | HIGH | ❌驳回 | 驳回：admin/views.py:362-363 的 shell 命令是 'killall -u %s' % user，而 user 来自同模块 os.popen('whoami') 的输出（服务进程自身用户名），没有外部可控数据进入命令串，不构成命令注入；B607 的部分路径执行在当前调用方式下无实际影响。该处真正 |
| C0024 | bandit | B405 | `app/wiki/views.py:17` | LOW | ❌驳回 | 驳回：wiki/views.py:17 的 import xml.etree.ElementTree as ET 经全文搜索确认只出现该导入行，ET 从未被使用，不存在对不可信 XML 的解析（C0038 的 rce 猜测同时被证伪）；lib/markdown/etree_loader.py:10,13 属纯内嵌库（l |
| C0025 | bandit | B411 | `lib/django_xmlrpc/decorators.py:41` | HIGH | ❌驳回 | 驳回：B411 命中的是 xmlrpclib/Fault 导入本身，这是本项目 XMLRPC 功能的基础依赖而非缺陷（lib/django_xmlrpc 为纯内嵌库；lib/ylinux_xmlrpc.py 确实在审但导入行为无误）；安全相关的真正缺陷是删除类方法只校验认证不校验对象归属，已记录为 F-003。 |
| C0026 | bandit | B405 | `lib/markdown/etree_loader.py:10` | LOW | ❌驳回 | 驳回：wiki/views.py:17 的 import xml.etree.ElementTree as ET 经全文搜索确认只出现该导入行，ET 从未被使用，不存在对不可信 XML 的解析（C0038 的 rce 猜测同时被证伪）；lib/markdown/etree_loader.py:10,13 属纯内嵌库（l |
| C0027 | bandit | B405 | `lib/markdown/etree_loader.py:13` | LOW | ❌驳回 | 驳回：wiki/views.py:17 的 import xml.etree.ElementTree as ET 经全文搜索确认只出现该导入行，ET 从未被使用，不存在对不可信 XML 的解析（C0038 的 rce 猜测同时被证伪）；lib/markdown/etree_loader.py:10,13 属纯内嵌库（l |
| C0028 | bandit | B101 | `lib/markdown/html4.py:184` | LOW | ❌驳回 | 驳回：两处 assert 均为内部不变式检查（account/middleware.py:19 在会话恢复后断言，lib/markdown/html4.py:184 在库内部），不是鉴权判定；Python -O 只会在主流程去掉断言，不会绕过任何权限检查（真正的鉴权缺失已在 F-003 记录）。 |
| C0029 | bandit | B411 | `lib/ylinux_xmlrpc.py:12` | HIGH | ❌驳回 | 驳回：B411 命中的是 xmlrpclib/Fault 导入本身，这是本项目 XMLRPC 功能的基础依赖而非缺陷（lib/django_xmlrpc 为纯内嵌库；lib/ylinux_xmlrpc.py 确实在审但导入行为无误）；安全相关的真正缺陷是删除类方法只校验认证不校验对象归属，已记录为 F-003。 |
| C0030 | bandit | B110 | `lib/ylinux_xmlrpc.py:28` | LOW | ❌驳回 | 驳回：lib/ylinux_xmlrpc.py:28 的 try/except/pass 包裹 isostring.split('.')[0]，仅用于容错解析 ISO 时间戳，不掩盖任何鉴权/校验分支；datetime_from_iso 的调用方也不以其异常作为安全判定。 |
| C0031 | bandit | B105 | `settings.py:32` | LOW | ❌驳回 | 驳回：三处命中均为 B105 字符串误报——account/models.py:44 的 '!'***'True' 是模板标记 PASSWORD_RESET_DONE，settings.py:32 的 EMAIL_HOST_PAS |
| C0032 | bandit | B105 | `settings.py:49` | LOW | ✅确认 | 命中：settings.py:49 的数据库口令 '***' 与 settings.py:79 的 SECRET_KEY 字面量硬编码在仓库中，已合并记录为 F-008。 |
| C0033 | bandit | B105 | `settings.py:79` | LOW | ✅确认 | 命中：settings.py:49 的数据库口令 '***' 与 settings.py:79 的 SECRET_KEY 字面量硬编码在仓库中，已合并记录为 F-008。 |
| C0034 | secret | secret/django_secret_key | `settings.py:79` | HIGH | ✅确认 | 命中：settings.py:49 的数据库口令 '***' 与 settings.py:79 的 SECRET_KEY 字面量硬编码在仓库中，已合并记录为 F-008。 |


### 4.2 收敛对账线索

收口前，引擎把**推理轨迹里提过、账本里却没有记录**的位置逐条提出来，要求模型逐条处置。它找的不是「引擎报的疑似漏洞」，而是「你说过这里、却没有留下任何结论」——实测漏报最主要的形态。

共 24 条：confirmed 2、dismissed 22

| 候选 | 线索类型 | 规则 | 位置 | 严重度 | 处置 | 理由 |
|---|---|---|---|---|---|---|
| C0035 | 提及对账 | mention | `app/ydata/views.py:78` | INFO | ✅确认 | 命中：ydata/views.py:78-84 用客户端文件名拼本地路径并直接 open(...,'wb+') 落盘，无 basename/规范化校验，已记录为路径穿越 F-010。 |
| C0036 | 提及对账 | mention | `settings.py:162` | INFO | ❌驳回 | 该位置随后已被 finding 覆盖（F-003）——系统自动回收：线索提出时该处尚无结论，现已有结论故不再追问。 |
| C0037 | 提及对账 | mention | `settings.py:100` | INFO | ❌驳回 | 该位置随后已被 finding 覆盖（F-003、F-008、F-009）——系统自动回收：线索提出时该处尚无结论，现已有结论故不再追问。 |
| C0038 | 提及对账 | mention | `app/wiki/views.py:1` | INFO | ❌驳回 | 驳回（wiki 应用已逐函数审完）：wiki/views.py:17 的 ElementTree 导入未使用，无 XXE；wiki/urls.py:50,51 的 ajax_show_posts 无鉴权且直接渲染帖子内容，但它只是把已登录用户提交的帖子（同 F-001 的持久 XSS 仓库）展示给更多读者，不构成独立于 |
| C0039 | 文件回访 | file | `lib/ylinux_xmlrpc.py:1` | INFO | ❌驳回 | 该文件随后已记录 finding 或已在证据里给出坐标（F-003）——系统自动回收：线索提出时该处尚无结论，现已有结论故不再追问。 |
| C0040 | 文件回访 | file | `app/ydata/forms.py:1` | INFO | ❌驳回 | 该文件随后已记录 finding 或已在证据里给出坐标（F-001）——系统自动回收：线索提出时该处尚无结论，现已有结论故不再追问。 |
| C0041 | 提及对账 | mention | `app/ydata/forms.py:1` | INFO | ❌驳回 | 驳回：ydata/forms.py 中 markup='none' 被硬编码使所有帖子按纯文本处理，这只会降低 markdown 能力，并不引入新的注入面；帖子正文直接交给模板 \|safe 的问题已在 F-001 记录，此硬编码不额外增加风险。 |
| C0042 | 提及对账 | mention | `app/wiki/utils.py:18` | INFO | ❌驳回 | 该位置随后已被 finding 覆盖（F-001）——系统自动回收：线索提出时该处尚无结论，现已有结论故不再追问。 |
| C0043 | 文件回访 | file | `app/ydata/views.py:1` | INFO | ❌驳回 | 该文件随后已记录 finding 或已在证据里给出坐标（F-001）——系统自动回收：线索提出时该处尚无结论，现已有结论故不再追问。 |
| C0044 | 文件回访 | file | `settings.py:1` | INFO | ❌驳回 | 该文件随后已记录 finding 或已在证据里给出坐标（F-003）——系统自动回收：线索提出时该处尚无结论，现已有结论故不再追问。 |
| C0045 | 文件回访 | file | `app/wiki/utils.py:1` | INFO | ❌驳回 | 该文件随后已记录 finding 或已在证据里给出坐标（F-001）——系统自动回收：线索提出时该处尚无结论，现已有结论故不再追问。 |
| C0046 | 文件回访 | file | `app/account/views.py:1` | INFO | ❌驳回 | 该文件随后已记录 finding 或已在证据里给出坐标（F-007）——系统自动回收：线索提出时该处尚无结论，现已有结论故不再追问。 |
| C0047 | 提及对账 | mention | `app/ydata/views.py:140` | INFO | ❌驳回 | 该位置随后已被 finding 覆盖（F-001、F-004）——系统自动回收：线索提出时该处尚无结论，现已有结论故不再追问。 |
| C0048 | 提及对账 | mention | `app/ydata/models.py:396` | INFO | ❌驳回 | 驳回：ydata/models.py:396 的 ylinux_text_filter 就是 F-001 中把帖子正文/附件名标记为安全 HTML 的那条过滤链的组成部分，本身不再是独立 sink，故并入 F-001。 |
| C0049 | 文件回访 | file | `app/wiki/urls.py:1` | INFO | ❌驳回 | 驳回（wiki 应用已逐函数审完）：wiki/views.py:17 的 ElementTree 导入未使用，无 XXE；wiki/urls.py:50,51 的 ajax_show_posts 无鉴权且直接渲染帖子内容，但它只是把已登录用户提交的帖子（同 F-001 的持久 XSS 仓库）展示给更多读者，不构成独立于 |
| C0050 | 文件回访 | file | `app/ydata/util.py:1` | INFO | ❌驳回 | 驳回（已逐行审完，无独立问题）：ydata/util.py 的 render_to/build_form/get_parents/ylinux_get_ip 是视图辅助函数，不直接执行危险操作；account/backends.py 的改造版 ModelBackend 权限查询已确认参数化（见 C0012）；accou |
| C0051 | 文件回访 | file | `app/wiki/views.py:1` | INFO | ❌驳回 | 驳回（wiki 应用已逐函数审完）：wiki/views.py:17 的 ElementTree 导入未使用，无 XXE；wiki/urls.py:50,51 的 ajax_show_posts 无鉴权且直接渲染帖子内容，但它只是把已登录用户提交的帖子（同 F-001 的持久 XSS 仓库）展示给更多读者，不构成独立于 |
| C0052 | 文件回访 | file | `app/account/backends.py:1` | INFO | ❌驳回 | 驳回（已逐行审完，无独立问题）：ydata/util.py 的 render_to/build_form/get_parents/ylinux_get_ip 是视图辅助函数，不直接执行危险操作；account/backends.py 的改造版 ModelBackend 权限查询已确认参数化（见 C0012）；accou |
| C0053 | 提及对账 | mention | `app/account/views.py:38` | INFO | ❌驳回 | 该位置随后已被 finding 覆盖（F-007）——系统自动回收：线索提出时该处尚无结论，现已有结论故不再追问。 |
| C0054 | 文件回访 | file | `app/account/__init__.py:1` | INFO | ❌驳回 | 驳回（已逐行审完，无独立问题）：ydata/util.py 的 render_to/build_form/get_parents/ylinux_get_ip 是视图辅助函数，不直接执行危险操作；account/backends.py 的改造版 ModelBackend 权限查询已确认参数化（见 C0012）；accou |
| C0055 | 提及对账 | mention | `app/ydata/views.py:91` | INFO | ✅确认 | 命中（与 F-005 同一判据）：ydata/views.py:91-95 同样把 attachment.name 与 notes 未转义地拼进 <script> 响应体（window.parent.AfterSubmit），与 F-005 是同一类缺陷的另一个报告点，修法已在 F-005 的 remediation  |
| C0056 | 文件回访 | file | `app/account/middleware.py:1` | INFO | ❌驳回 | 驳回（已逐行审完，无独立问题）：ydata/util.py 的 render_to/build_form/get_parents/ylinux_get_ip 是视图辅助函数，不直接执行危险操作；account/backends.py 的改造版 ModelBackend 权限查询已确认参数化（见 C0012）；accou |
| C0057 | 提及对账 | mention | `app/wiki/urls.py:50` | INFO | ❌驳回 | 驳回（wiki 应用已逐函数审完）：wiki/views.py:17 的 ElementTree 导入未使用，无 XXE；wiki/urls.py:50,51 的 ajax_show_posts 无鉴权且直接渲染帖子内容，但它只是把已登录用户提交的帖子（同 F-001 的持久 XSS 仓库）展示给更多读者，不构成独立于 |
| C0058 | 文件回访 | file | `app/account/decorators.py:1` | INFO | ❌驳回 | 驳回并留下覆盖结论：app/account/decorators.py 全文（1-82 行）已逐行审阅，它是 Django 早期 contrib.auth 装饰器的转写（user_passes_test / login_required / permission_required / _CheckLogin）。逻辑本身 |


## 五、外部入口与鉴权状态

共 110 个外部入口：**21 个无认证**，**12 个有认证但未见对象级授权**。

> **认证与授权是两件事**：认证回答「你是谁」，授权回答「你能动谁」。「有认证、未见对象级授权」是**待核验线索**而非结论——读全局列表类的操作本就不需要对象级校验，而删除他人资源的需要。

### 5.1 无认证入口

| 类型 | 位置 | 目标 | 说明 |
|---|---|---|---|
| http_route | `app/account/urls.py:6` | `^$` |  |
| http_route | `app/account/urls.py:8` | `^register/(?P<key>.+)/$` |  |
| http_route | `app/account/urls.py:10` | `^logout/$` |  |
| http_route | `app/admin/urls.py:7` | `^$` |  |
| http_route | `app/bbs/urls.py:7` | `^$` |  |
| http_route | `app/blog/urls.py:6` | `^$` |  |
| http_route | `app/home/urls.py:7` | `^$` |  |
| http_route | `app/home/urls.py:9` | `^about/$` |  |
| http_route | `app/home/urls.py:10` | `^contact/$` |  |
| http_route | `app/home/urls.py:11` | `^coding/$` |  |
| http_route | `app/home/urls.py:12` | `^sitemap.txt/$` |  |
| http_route | `app/home/urls.py:13` | `^robots.txt/$` |  |
| http_route | `app/me/urls.py:6` | `^$` |  |
| http_route | `app/wiki/urls.py:9` | `^$` |  |
| http_route | `app/wiki/urls.py:28` | `^catalog/(?P<id>\d+)/addtopic/$` |  |
| http_route | `app/wiki/urls.py:50` | `^topic/(?P<topicID>\d+)/ajax_show_posts/$` |  |
| http_route | `app/wiki/urls.py:51` | `^post/(?P<postID>\d+)/ajax_show_posts/$` |  |
| http_route | `app/ydata/urls.py:9` | `^attachment/(?P<id>\d+)/download/$` |  |
| http_route | `app/ylab/urls.py:6` | `^time$` |  |
| http_route | `app/ylab/urls.py:8` | `^update_post_profile$` |  |
| http_route | `urls.py:47` | `^xmlrpc/$` |  |

### 5.2 有认证、未见对象级授权的入口

| 类型 | 位置 | 目标 | 认证依据 |
|---|---|---|---|
| xmlrpc | `settings.py:165` | `delete_topic` | 函数体内调用 has_auth() |
| xmlrpc | `settings.py:166` | `delete_all_topic` | 函数体内调用 has_auth() |
| xmlrpc | `settings.py:169` | `metaWeblog.newPost` | 函数体内调用 has_auth() |
| xmlrpc | `settings.py:170` | `metaWeblog.newMediaObject` | 函数体内调用 has_auth() |
| xmlrpc | `settings.py:171` | `metaWeblog.editPost` | 函数体内调用 has_auth() |
| xmlrpc | `settings.py:172` | `metaWeblog.getPost` | 函数体内调用 has_auth() |
| xmlrpc | `settings.py:173` | `metaWeblog.getCategories` | 函数体内调用 has_auth() |
| xmlrpc | `settings.py:174` | `metaWeblog.getRecentPosts` | 函数体内调用 has_auth() |
| http_route | `app/account/urls.py:9` | `^login/$` | 装饰器：["render_to('***')"]；函数体内调用 authenticate() |
| http_route | `app/account/urls.py:15` | `^login/ajax/$` | 装饰器：["render_to('***')"]；函数体内调用 authenticate() |
| http_route | `app/admin/urls.py:8` | `^login/$` | 装饰器：["render_to('***')"]；函数体内调用 authenticate() |
| http_route | `app/wiki/urls.py:31` | `^topic/(?P<id>\d+)/edit/$` | 装饰器：无；函数体内调用 has_auth() |

## 六、代码归因

**归因决定了缺陷算谁的。** 原样拷贝的第三方库不计入项目漏洞（但需要安排升级）；被项目改造过的 fork 则**计入项目**。

| 归因 | 文件数 | 说明 |
|---|---|---|
| project | 66 | 项目自有代码 |
| vendored | 38 | 原样引入的第三方库 |
| suspected | 1 | 归因待人工裁决 |

### 6.1 改造版第三方代码（2 个）——**缺陷归项目**

| 文件 | 源自 | 判定依据 |
|---|---|---|
| `app/account/backends.py` | django | 反向证据：import 了 1 个仓库内非 vendored 模块（account.models → app/account/models.py）——已被项目改造，**缺陷归项目所有**；符号签名：定义了 1 个 django 独有符号（ModelBackend）；引用 3 个 django API |
| `app/account/middleware.py` | django | 反向证据：import 了 1 个仓库内非 vendored 模块（account → app/account/__init__.py）——已被项目改造，**缺陷归项目所有**；符号签名：定义了 1 个 django 独有符号（LazyUser）；引用 1 个 django API |

### 6.2 待裁决（1 个）

- `lib/__init__.py` — 来源未知

## 七、附录

### 7.1 审计范围

- 仓库文件总数：105
- 在审文件：40（已排除归因明确为 vendored、解析失败、无实质代码、以及 8 个排除项）

### 7.2 引擎运行统计

| 引擎 | 状态 | 命中 | 分析文件 | 跳过 |
|---|---|---|---|---|
| semgrep | ✅ | 11 | 292 | 0 |
| bandit | ✅ | 22 | 96 | 9 |
| secret | ✅ | 1 | 91 | 0 |

### 7.3 Agent 工具调用统计

| 工具 | 调用次数 | 失败次数 |
|---|---|---|
| read_code | 107 | 0 |
| search_code | 17 | 0 |
| record_finding | 11 | 0 |
| list_candidates | 8 | 1 |
| adversarial_verify | 6 | 0 |
| check_vendored | 5 | 0 |
| outline | 5 | 0 |
| list_files | 4 | 0 |
| dispose_candidates | 3 | 0 |
| set_coverage | 2 | 0 |
| get_entry_points | 1 | 0 |
| find_callers | 1 | 0 |
| conclude | 1 | 0 |
| **合计** | **171** | **1** |

### 7.4 审计轨迹

账本记录事件 339 条，含每次工具调用、每次账本变更与完整的覆盖度依据（见同目录 ledger.json）。

Agent 推理轨迹 51 条（其中思考 50 条）。**轨迹是 Agent 当时的自述，不是核验过的事实**——可核验的是每条 finding 的 evidence 字段；保留轨迹是为了让「它何时说了什么」可被复核。

- **第 1 轮**（思考）Let me start by getting the entry points and candidates, and listing files. Let me start with reconnaissance: list_files, get_entry_points, list_candidates. I'll do multiple independent calls in one block.
- **第 1 轮**（输出）我先做侦察：确认范围、入口和候选。
- **第 2 轮**（思考）Let me plan. Key files to audit: entry points, especially unauthenticated ones. Let me read the main view files. Priority: admin/views.py (13 open-redirect candidates), account files, wiki/views.py, ydata/views.py (py2), lib/ylinux_xmlrpc.py, app/ylab/views.py (unauthenticated update_post_profile!),…
- **第 3 轮**（思考）Notable: app/ylab/views.py update_post_profile is unauthenticated (no decorator) and writes all posts — bulk data modification. Also upload_single_file unauthenticated, arbitrary file upload (though it doesn'***'s note. lib/__init__.py — need to read to decide attribution. Let me now read a…
- **第 4 轮**（思考）lib/__init__.py: it's django's version module (lib 是 django 的 top-level package?). Actually lib/__init__.py defines VERSION = (1,1,1,'final',0) and get_version using django.utils.version.get_svn_revision, with get_svn_revision returning u'SVN-unknown' — this format matches Django's 1.1 django/__init…
- **第 5 轮**（思考）Important: lib/ylinux_xmlrpc.py new_media: file_name = fileObject['name'].encode('utf8'); dated_path uses os.path.basename(file_name) — basename mitigates traversal. target_path = os.path.join(settings.MEDIA_ROOT, relative_path). basename applied → traversal mitigated. But `settings` is not imported…
- **第 6 轮**（思考）Key observations so far: ydata/views.py download_attachment (line 117-149): NO @login_required, entry point `ydata/urls.py:9 ^attachment/(?P<id>\d+)/download/$` unauthenticated. It reads file at a.get_absolute_path() and serves it. Attachment includes private-ish content. Any anonymous user with an …
- **第 7 轮**（思考）Now I see the open-redirect candidates: `HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))` at lines 134, 192, 257, 354 — semgrep flags them as open redirect. In Django, HttpResponseRedirect with an external URL is an open redirect. HTTP_REFERER is attacker-controllable in the sense that t…
- **第 8 轮**（思考）I need account/models.py key parts: User.has_perm (256-277), UserManager.make_random_password (143-148), set_password/check_password (228-250), Register (389-430), create_activate_user (371-386). And account/views.py 130-254 (rest: reset password, ajax login). Also ydata/models.py for attachment pat…
- **第 9 轮**（思考）Important: User.has_perm → superuser True; otherwise backends. So 'just_admin_can_delete' isn't automatically superuser-only... but superuser returns True always. So del_user requires the permission; only superuser (or whoever has that perm) can do it. That comment "只有 superuser 可以验证为 True" is rough…
- **第 10 轮**（思考）Key finding candidate: password reset. `password_reset_request` requires knowing the email; but `/account/password/reset/<key>/` — key = activation_key of a Register row. Notably, the activation key used for registration is the SAME field used for password reset, and `create_activate_user` sets `pro…
- **第 11 轮**（思考）Now I have the attachment findings: **F: download_attachment 无鉴权 IDOR + 任意文件读取 via path traversal** - `download_attachment(request, id)` at ydata/views.py:117 — no @login_required. Entry: `ydata/urls.py:9 ^attachment/(?P<id>\d+)/download/$` (listed as unauth). - It opens `a.get_absolute_path()` = ME…
- **第 12 轮**（思考）Key: `Markdown(...).convertFile(..., myfilter=ylinux_text_filter)` — markdown 1.x old version with myfilter (a "markdown 1.7" style extension?). In old markdown, `safe_mode` default was 'replace'? Actually in Markdown 1.7/2.x, safe_mode default False (i.e., HTML passthrough). Let's check vendored ma…
- **第 13 轮**（思考）Let me read Post.save (models 227-290) and the ylinux_text_filter (390-452). Also check templates: app/wiki/utils.py showed `{{ post.body_html|safe }}`. So body_html is rendered with |safe. And for `markup == 'none'` (line 260), `Markdown(extensions=['fenced_code']).convert(ylinux_text_filter(self.b…
- **第 14 轮**（思考）Now, XSS chain: Post.save with markup='none' → no safe_mode → raw HTML. Topic.save_file → convertFile with safe_mode default False → raw HTML in topic body passes through. Rendered |safe. But wait: for Post, `urlize` is applied after — urlize escapes? `django.utils.html.urlize` does escape the text?…
- **第 15 轮**（思考）Great findings: 1. `backends.py:43-57` B608: sql built with `%` but all interpolated values are quoted identifiers from `qn()` (fixed literals) — not user input; `user_obj.id` passed as parameter. → dismiss C0012 with concrete reason. 2. AddTopicForm/EditTopicForm: `markup` comes from `fields = ['ca…
- **第 16 轮**（思考）Now read wiki/views.py add_post (134-161) and ajax_show_posts (368-388), and replayAJAX (396-444) — ajax_show_posts is an unauthenticated entry (urls.py:51). Let me read 130-210 and 360-400. Also, Post.save with markup='***' from AddPostForm → raw HTML. But wait: is there any escaping of the body b…
- **第 17 轮**（思考）ajax_show_posts (368-388) has NO login_required and renders post.body_html via render_post → |safe. Entry: wiki/urls.py:51 `^post/(?P<postID>\d+)/ajax_show_posts/$` (unauth) and :50 topic variant. So stored XSS is delivered unauthenticated to any viewer. So finding: Stored XSS. Source: post body via…
- **第 18 轮**（思考）Note lib/ylinux_xmlrpc.py: `delete_all_topic(user, passwd)` only requires authentication (has_auth = authenticate) — any authenticated user (any registered account) can delete ALL topics. That's a privilege issue: no staff/permission check. Also delete_topic, get_recent_topics. Is the XMLRPC entry "…
- **第 19 轮**（思考）settings.py:79 is a SECRET_KEY (assigned, redaction marker `<assigned_secret:...>` — the tool redacted it, meaning it's a real secret in the file). Candidate C0033 at line 79 likely "***". Also 49 DB password '***' (C0032?). And EMAIL_HOST_PASSWORD = '' empty (not a secret). Line…
- **第 20 轮**（思考）Important: settings.py XMLRPC_METHODS references `ylinux_xmlrpc.new_topic` and `ylinux_xmlrpc.edit_topic` — need to see if those functions exist in lib/ylinux_xmlrpc.py (lines 161-252 truncated earlier). Let's read 160-252 of lib/ylinux_xmlrpc.py. Key: new_topic / edit_topic — they call has_auth the…
- **第 21 轮**（思考）Confirmed settings.py:18 DEBUG=True → C4 finding (debug enabled in shipped code; exposes tracebacks, settings; combined with non-debug-safe behaviour). Now key findings to record: F1: Stored XSS in wiki posts (markdown raw HTML passed through, rendered with |safe) — need to confirm `Topic.save_file`…
- **第 22 轮**（思考）Key confirmations: - Post.save: markup '***' → `Markdown(extensions=['***']).convert(ylinux_text_filter(self.body))` — no safe_mode → raw HTML preserved. Then body_html rendered with |safe in wiki/utils.py:18 via render_post, and ajax_show_posts (unauth entry) returns it. Also show_topic te…
- **第 23 轮**（思考）Let me plan. Budget 22/50 rounds. I still need a lot: coverage of 7 classes, 34 candidates, findings. Key remaining work: 1. Post markup='none' stored XSS — need to verify markup field is user-settable in AddPostForm. Let me read ydata/forms.py lines 1-60 (AddPostForm uses markup='none' hardcoded — …
- **第 24 轮**（思考）Now I have a clearer picture. Open redirect: admin/views.py:62 `return HttpResponseRedirect(request.session.get('previous_url','/'))` — the session value was set at line 65 from HTTP_REFERER. Session is server-side; attacker can't set another user's session. Hmm — but wait, the open redirect: `reque…
- **第 25 轮**（思考）Key confirmations: 1. Post.save line 251-262: markup 'bbcode' → bbmarkup.bbcode(body); 'markdown' → safe_mode='escape'; 'none' → `Markdown(extensions=['fenced_code']).convert(ylinux_text_filter(self.body))` — no safe_mode → raw HTML preserved. AddPostForm hardcodes markup='none' for every new post! …
- **第 26 轮**（思考）I need to handle recall clues C0035-C0040 and dispose candidates. Also record findings. Let me now be decisive and start recording findings. Confirmed items so far: **F1: Stored XSS via Post markup='none' + `|safe` render** (C1). - sink: app/ydata/models.py:260 `Markdown(extensions=['fenced_code']).…
- **第 27 轮**（思考）Now let me record findings. First the XSS chain. I need to confirm the details from ydata/models.py Post.save (lines ~245-265) and ydata/forms.py AddPostForm.save (line ~40-60) and wiki/utils.py render_post (lines 1-36). I read those files earlier but let me re-verify key lines precisely with a narr…
- **第 28 轮**（思考）Now I have the XSS chain solid: - AddPostForm.save (app/ydata/forms.py:46) hardcodes markup='none' with user body. - Post.save with markup='none' → Markdown.convert(ylinux_text_filter(body)) without safe_mode → raw HTML preserved in body_html (need to confirm ydata/models.py lines ~245-265 exactly; …
- **第 29 轮**（思考）Now record the findings. Let me start with the stored XSS chain (C1), HIGH. Finding F-001: Stored XSS in wiki posts via markup='none' + `|safe`. - sink: ydata/models.py:260 (Markdown without safe_mode) → body_html; rendered raw at wiki/utils.py:18. - source: request.POST['body'] via AddPostForm (yda…
- **第 30 轮**（思考）ylinux_text_filter — where is it defined? Not in util.py 1-176? I searched earlier and saw mentions. Let me grep for "def ylinux_text_filter". Actually the smoke: models.py imports it. Let me search. Also, key: markup='none' path applies `Markdown(extensions=['fenced_code']).convert(ylinux_text_filt…
- **第 31 轮**（思考）Now record findings. Key confirmed items: 1. Stored XSS: ydata/models.py:396 ylinux_text_filter — let me check it. I need lines ~250-270 (markdown) and 390-410 (ylinux_text_filter). I read models.py 1-353 (78%). So 390-410 unread. Let me read 240-280 and 390-410 later — actually I recorded earlier t…
- **第 32 轮**（思考）Now I have plenty. Let me record findings now (several). Then handle candidates/recall lines. Findings to record: F-001 (HIGH, C1_注入, XSS stored): `|safe` rendering of Markdown-converted post body with markup='none' → raw HTML preserved. Need exact lines: ydata/models.py body_html property. I read m…
- **第 33 轮**（思考）Important: password_reset at account/views.py:202 — the key is `register.activation_key`, and `password_reset_request` resets/creates it. Key is 40-hex sha1(salt+email) with salt = 5 hex chars from random.random() → 5 hex chars = 20 bits of entropy from Mersenne Twister seeded by time. But to attack…
- **第 34 轮**（思考）Key confirmations: 1. `ylinux_text_filter` produces `<a href="%s">%s</a>` with `a.name` unescaped — and the output goes into Markdown + `|safe`. Attachment name is user-supplied (post author uploads attachment with arbitrary name) → stored XSS. But wait, does `Attachment.objects.get(pk=id)` — the li…
- **第 35 轮**（思考）Now I have solid evidence for: - ylab update_post_profile lines 37-48: unauthenticated mass mutation. Confirmed no login_required decorator (imports login_required but doesn'***'s v…
- **第 36 轮**（思考）Now important new facts: - MIDDLEWARE_CLASSES does NOT include CsrfViewMiddleware → all state-changing GET endpoints are CSRF-able. Also sessions/auth middleware are the project's forked ones (ylinux.app.sessions.middleware, ylinux.app.account.middleware) — note the "***" prefix and paths; the in…
- **第 37 轮**（思考）Search for IE_sanitize found only ylinux_xmlrpc.py:120 (basename). No django vendored copy in the repo?? That means Django itself is not in the repo (only lib/ contains django_xmlrpc). So the sanitization behavior of Django's file upload can't be confirmed from the repo → mark as needs-human / condi…
- **第 38 轮**（思考）Interesting: the verifier ran out of budget (static undecidable → needs human). The ledger says "3 条 HIGH/CRITICAL 未经对抗验证" earlier; now presumably the verifies count as done (need to check on conclude). It said "🟡 静态无法判定，需人工复核：验证者未在预算内提交结论" — that counts as verified? Probably counts as attempted; ma…
- **第 39 轮**（思考）Key findings from reads: - backends.py:43-57 B608 candidate: SQL built with `%` but all interpolated values are `qn()`-quoted identifiers; user id via parameter `%s` placeholder → cursor.execute(sql, [user_obj.id]). So NOT injectable → dismiss C0012 with precise reasoning. - account/models.py:143-14…
- **第 40 轮**（思考）Now I have: - admin/views.py:62: `HttpResponseRedirect(request.session.get('previous_url','/'))` and line 65 sets previous_url from HTTP_REFERER. So the open redirect chain: GET /admin/login/ with Referer: http://evil.com → session previous_url = evil.com → after successful staff login → redirect to…
- **第 41 轮**（思考）Big one found: app/admin/views.py:362-363: `user=os.popen('whoami').read().strip()` and `os.system('killall -u %s' % user)`. That's the reboot view (route ^reboot/$ required admin). The 'whoami' output isn't user-controlled... but if user = 'root'? killall -u root. Hmm, injection requires controllin…

> 另有 9 条未在此展开（篇幅所限）。完整文本见 `audit-report.json` 的 `agent.transcript`。

### 7.5 数据外发声明

本次审计向外部 LLM 服务发送了代码内容用于分析。**累计发送 1,954,431 tokens**，= 输入 382,847 + 缓存读 1,571,584 + 缓存写 0。（输出 98,985 tokens **不计入**：那是模型生成的内容，不是送出去的东西。）

这个数字取自服务端回报的 usage（`input_tokens` + `cache_read_input_tokens` + `cache_creation_input_tokens`），而非本地估算。三点须说明：

- **缓存读不等于「本轮又发了一遍」**。它指服务端在上一轮已经收到的前缀，本轮由服务端从缓存中读取、**没有经网络重新传输**。把它计入，是因为这些内容**此刻仍存在于对方服务端**——对一份数据外发声明来说，「还在不在那里」比「这一轮有没有再发」更要紧。
- **本地估算不能用作此数**：实测同一段文本，本地 `estimate()` 报 4,474，服务端实际收到 3,405（**高估 31%**）。所以要报就报服务端回报的。
- 该端点**自动做前缀缓存**（本工具从不发送 `cache_control` 断点），因此缓存读占比高是正常的，不表示外发量被重复计算。

若被审代码含敏感信息，请确认已按组织的数据分级要求处理。

### 7.6 凭据清单（值已脱敏）

> 本表**不含凭据明文**：只保留类型、长度、前 3 位与 SHA256 指纹。前 3 位用于人工确认凭据类型；指纹用于判断多处出现的是否为同一个值。需要原值请到源码对应位置查看——报告本身不是密钥的传播渠道。

| 类型 | 位置 | 长度 | 指纹 | 预览 | 出现处 |
|---|---|---|---|---|---|
| `django_secret_key` | `settings.py:79` | 50 | `f5038eced716` | `c#0***` | `settings.py:79` |

**处置顺序**：先轮换凭据，再改代码。反过来做会让轮换失去紧迫感，而已经扩大的暴露面并不会因为代码改好了而缩小。

### 7.7 构建指纹

同一靶子上的两次运行，只有在**代码与配置都相同**时才谈得上对照。本节把这句话变成可核的：把两份报告的 `code_digest` 摆在一起比一下即可。**不同就是不具可比性**——任何「这次比上次好」的结论都不成立，因为改变的可能是工具本身，而不是模型的表现。

- 代码指纹：`e844a6d55780dc7e`（`engine/` + `audit.py` 共 28 个文件）
- 配置快照：`agent_enabled=True`、`max_turns=50`、`max_tokens=***`、`compact_at_ratio=0.6`、`require_adversarial_for=['***', '***']`、`recall_enabled=True`、`recall_after_ratio=0.5`、`recall_max_mention=4`、`recall_max_file=2`、`recall_max_total=6`、`recall_max_mention_total=6`、`recall_max_file_total=6`、`provider=auto`、`model=deepseek-v4-flash`、`max_output_tokens=8192`

---

*本报告由 ai-audit 生成。报告中所有结论的覆盖范围以第二节为准；标注为「需人工确认」的条目在人工核验前不应作为决策依据。*