一个 SEO 用的网站扫描器(爬虫型审计工具),按模块列出核心功能:

## 1. 爬取引擎(基础)
- 起始 URL / sitemap.xml 种子,遵守 robots.txt(可开关)
- 并发、速率限制、超时、重试、深度/页数上限
- 域内/子域/外链范围控制,URL 规范化与去重(参数、锚点、大小写、尾斜杠)
- 可选 JS 渲染(无头浏览器),对比"源码 HTML vs 渲染后 DOM"
- 自定义 UA、Cookie/鉴权头、增量重爬与结果对比

## 2. 链接检查
- **死链**:4xx/5xx、超时、DNS 失败、连接重置
- **重定向**:301/302/307/308、重定向链长度、重定向环、HTTP→HTTPS 混合
- **外链**:状态码、`nofollow/sponsored/ugc`、外链域名汇总、外链被 robots 拦截
- **内链**:每页入链/出链数、孤儿页(sitemap 有但无入链)、点击深度、锚文本分布、内链指向非规范 URL
- 每条死链要记录**来源页 + 锚文本 + 位置**,否则无法修复

## 3. 页面级 SEO 元素
- title / meta description:缺失、重复、过长/过短
- H1~H6:缺失、多个 H1、层级跳跃
- canonical:缺失、自指、指向 404/重定向/非索引页、与实际冲突
- meta robots / X-Robots-Tag:noindex/nofollow 冲突
- hreflang:互指是否闭环、语言代码合法性
- Open Graph / Twitter Card
- 结构化数据(JSON-LD/Microdata)解析与 schema 校验
- 图片 alt 缺失、图片过大、无尺寸属性
- 内容:字数、薄内容、重复/近似重复内容(simhash)
- URL 质量:过长、含大写/下划线/过多参数

## 4. 索引与抓取性
- robots.txt 解析与规则测试,sitemap 校验(URL 状态、是否被 noindex、是否漏页)
- 可抓取但 noindex、被 robots 封却在 sitemap 的矛盾项
- 分页(rel next/prev 已弃用,但仍查分页结构)、无限参数/爬虫陷阱识别

## 5. 性能
- 服务端:TTFB、下载耗时、响应大小、压缩(gzip/br)、缓存头(Cache-Control/ETag)
- HTTP 版本(h2/h3)、连接复用
- 前端(需浏览器):LCP、CLS、INP、FCP,资源数量与体积、阻塞渲染的 CSS/JS、未优化图片格式(WebP/AVIF)
- 可对接 Lighthouse / PageSpeed Insights API 抽样,全站逐页跑成本高,建议"全站 TTFB + 抽样 CWV"

## 6. 安全与技术
- HTTPS 证书有效期/链、HSTS、混合内容
- 安全响应头(CSP、X-Frame-Options 等)
- www/非 www、http/https 四种入口是否统一跳转
- 软 404(返回 200 但内容是"未找到")、自定义 404 页检测
- 移动端适配(viewport meta)

## 7. 报告与工程化
- 问题分级(错误/警告/提示)+ 影响页面数 + 优先级
- 每个问题可下钻到 URL 列表,支持导出 CSV/JSON
- 两次扫描 diff(新增/修复/回归问题)
- 站点结构可视化(目录树、链接图)
- 定时任务、CI 集成、阈值告警
- API/CLI 输出,方便你做成单二进制服务

## 开发优先级建议
1. **MVP**:爬取 + 状态码/死链/重定向链 + title/meta/H1/canonical + 来源页追踪 + CSV 导出
2. 第二步:sitemap/robots 校验、孤儿页、重复内容、TTFB/压缩/缓存
3. 第三步:JS 渲染、CWV、结构化数据、扫描对比

最容易被低估的是**URL 规范化去重**和**爬虫陷阱防护**,这两处做不好,结果会大量失真。