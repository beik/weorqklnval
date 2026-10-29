# 节点目录自动校验

`verify-node-catalog` 使用目标分支上的可信代码和 RSA 公钥验证 PR 中的三个 ZPN1 文件。
不执行 PR 中的任何脚本，不使用签名私钥、数据库账号或 `.197` Token；Actions 只读仓库内容，
额外允许写入 commit status，将 `verify-node-catalog` 结果绑定到准确的 PR head SHA。
检查限定文件范围、签名/摘要、市场、90天有效期、非空节点/分组、快照一致性及版本/签发时间回退。
日志仅输出版本、节点数和 hash，不输出节点配置。

## 首次启用

1. 人工审查并合并工作流安装 PR。此 PR 包含校验代码，不属于每日数据 PR。
2. 打开 Actions → Verify node catalog → Run workflow，填写当前待发布的节点 PR 编号。
   这会验证该 PR，并明确将状态写入该 PR head SHA；之后新 PR/更新会自动触发。
3. 等检查成功，在 main Ruleset 的 Require status checks to pass → Add checks 中添加
   `verify-node-catalog`（来源 GitHub Actions），建议开启 Require branches to be up to date before merging。
4. 合并节点 PR 后，从 Raw main 回读三个文件并核对 hash。

工作流使用 base SHA 执行；如等待期间 main 已变化，旧任务会停止，须用最新 base 重新触发。
校验器/公钥/工作流自身的维护 PR 会被每日数据的路径白名单拒绝，需要人工审查并执行一次受控的规则维护；不能自动合并此类变更。

本工作流只提供检查，不执行合并。`.197` 发布器启用 auto-merge 前必须确认 main 已要求此检查。

本地测试：`node --test catalog-ci/verify.test.mjs`。
