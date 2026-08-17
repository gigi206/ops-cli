# Secrets — injecting credentials without letting them into the cage

One provider per subdirectory. What is common to all of them lives **here**;
each provider's page only carries what is specific to it (host, variable, its
motivation, how to verify against *that* service). Read this page first.

## The invariant

A cage inherits exactly `TERM`, `LANG`, `LC_ALL` from the host — a token set in
your shell is correctly invisible inside the sandbox, on purpose. The real key
is read **host-side** by sbx and injected by the filtering egress proxy **on
the wire** into the matching outbound request; the agent at most sees the
request it was going to make anyway, with no token anywhere in its environment
or filesystem. A credential therefore belongs in `[secret]`, **not** in `[env]`
(which is visible inside the cage).

## The block

Every provider page here is a `[secret]` table keyed by the **destination
host** — the section name *is* the destination:

```toml
[secret."<host>"]
from   = "env://<VARIABLE_NAME>"
header = "Authorization"
type   = "bearer"
```

| Line | Meaning |
|---|---|
| `[secret."<host>"]` | the section is the destination host; a credential bound to exactly that host (a wildcard is rejected as an injection target) |
| `from = "env://<VARIABLE_NAME>"` | the **source**: resolved host-side from sbx's own environment, never inside the cage |
| `header = "<name>"` | the header the proxy sets on the matching outbound request |
| `type = "bearer"` | how to shape the value (below) |

The `header` and `type` are the only two things that vary per provider —
look at the provider page for which set to use.

## The `type` shapes

| `type` | Header value | Use when |
|---|---|---|
| `bearer` | `Authorization: Bearer <token>` | the service accepts a token in `Authorization` (most providers) |
| `basic` | `Authorization: Basic <base64(user:pass)>` | the credential is a `user:pass` pair (sbx base64-encodes it — the agent never pre-encodes) |
| `raw` | `<header>: <token>` | a non-`Authorization` header or a non-standard scheme (`token `, `ApiKey `, … via `prefix`) |

`header` and `type` are required — sbx refuses a secret that names neither
rather than silently defaulting. sbx's value is **authoritative**: any
client-supplied copy of the header is stripped and replaced.

## When it injects (and what sbx refuses to do)

Injection is performed by the filtering egress proxy, so it is **effective
only** under a **filtering network posture** (`deny`/`allow`/`ask`); under
`shared`/`none` there is no proxy on the wire and the `[secret]` injects
nothing. The destination must also be reachable under the cage's egress
allowlist — each provider page states its host.

If the source cannot produce a value (`env://` variable unset, …) sbx **fails
closed**: the launch is refused naming the source, never sent unauthenticated.

## Scoping it deliberately

Injection keys a request *as you* within what the cage's egress allowlist
already permits. Declared in the global `sbx.toml`, every cage that can reach
the host gets its requests authenticated as you; declared under
`[app.<name>.secret]`, the block stays that one app's. Egress remains an
allowlist either way.

## Verifying

```sh
sbx config show            # "secrets: N injected host-side" (values never shown)
sbx config show --details  # each credential by destination host and source
sbx secret list            # inventory, by name and destination
```

Plus, from inside a cage, call an authenticated endpoint of the service — each
provider page says which one to read and what proves the header arrived.

## Providers

| Provider | Host | Variable | `header` / `type` |
|---|---|---|---|
| [Alibaba (Qwen)](alibaba/) | `dashscope-intl.aliyuncs.com/compatible-mode/v1/*` | `env://DASHSCOPE_API_KEY` | `Authorization` / `bearer` |
| [Alibaba (Qwen, CN)](alibaba-cn/) | `dashscope.aliyuncs.com/compatible-mode/v1/*` | `env://DASHSCOPE_API_KEY` | `Authorization` / `bearer` |
| [Anthropic](anthropic/) | `api.anthropic.com/v1/*` | `env://ANTHROPIC_API_KEY` | `Authorization` / `bearer` |
| [Baseten](baseten/) | `inference.baseten.co/v1/*` | `env://BASETEN_API_KEY` | `Authorization` / `bearer` |
| [ByteDance (Doubao)](bytedance/) | `ark.cn-beijing.volces.com/api/v3/*` | `env://ARK_API_KEY` | `Authorization` / `bearer` |
| [Cerebras](cerebras/) | `api.cerebras.ai/v1/*` | `env://CEREBRAS_API_KEY` | `Authorization` / `bearer` |
| [Cloudflare](cloudflare/) | `api.cloudflare.com/client/v4/accounts/*/ai/v1/*` | `env://CLOUDFLARE_API_TOKEN` | `Authorization` / `bearer` |
| [Cohere](cohere/) | `api.cohere.com/v2/*` | `env://COHERE_API_KEY` | `Authorization` / `bearer` |
| [DeepInfra](deepinfra/) | `api.deepinfra.com/v1/*` | `env://DEEPINFRA_API_KEY` | `Authorization` / `bearer` |
| [DeepSeek](deepseek/) | `api.deepseek.com/*` | `env://DEEPSEEK_API_KEY` | `Authorization` / `bearer` |
| [Fireworks AI](fireworks-ai/) | `api.fireworks.ai/inference/v1/*` | `env://FIREWORKS_API_KEY` | `Authorization` / `bearer` |
| [Flux (BFL)](flux/) | `api.bfl.ai/*` | `env://BFL_API_KEY` | `x-key` / `raw` |
| [GitHub](github/) | `api.github.com` | `env://GITHUB_TOKEN` | `Authorization` / `bearer` |
| [GitHub Copilot](github-copilot/) | `api.individual.githubcopilot.com/*` (session token, 30 min) | `env://GITHUB_COPILOT_API_TOKEN` | `Authorization` / `bearer` |
| [Google (Gemini)](google/) | `generativelanguage.googleapis.com/v1beta/*` | `env://GEMINI_API_KEY` | `x-goog-api-key` / `raw` |
| [Groq](groq/) | `api.groq.com/openai/v1/*` | `env://GROQ_API_KEY` | `Authorization` / `bearer` |
| [Hugging Face](huggingface/) | `router.huggingface.co/v1/*` | `env://HF_TOKEN` | `Authorization` / `bearer` |
| [Kimi](kimi/) | `api.kimi.com/coding/v1/*` | `env://KIMI_API_KEY` | `Authorization` / `bearer` |
| [Kilo](kilo/) | `api.kilo.ai/api/gateway/*` | `env://KILO_API_KEY` | `Authorization` / `bearer` |
| [Kling AI](kling/) | `api-singapore.klingai.com/*` | `env://KLINGAI_API_KEY` | `Authorization` / `bearer` |
| [Llama (Meta)](llama/) | `api.llama.com/compat/v1/*` | `env://LLAMA_API_KEY` | `Authorization` / `bearer` |
| [Luma (Dream Machine)](luma/) | `api.lumalabs.ai/dream-machine/v1/*` | `env://LUMA_API_KEY` | `Authorization` / `bearer` |
| [Meta AI](meta-ai/) | `api.meta.ai/v1/*` | `env://MODEL_API_KEY` | `Authorization` / `bearer` |
| [MiniMax](minimax/) | `api.minimax.io/v1/*` | `env://MINIMAX_API_KEY` | `Authorization` / `bearer` |
| [Mistral](mistral/) | `api.mistral.ai/v1/*` | `env://MISTRAL_API_KEY` | `Authorization` / `bearer` |
| [Moonshot](moonshot/) | `api.moonshot.ai/v1/*` | `env://MOONSHOT_API_KEY` | `Authorization` / `bearer` |
| [NVIDIA](nvidia/) | `integrate.api.nvidia.com` | `env://NVIDIA_API_KEY` | `Authorization` / `bearer` |
| [Ollama](ollama/) | `ollama.com/v1/*` | `env://OLLAMA_API_KEY` | `Authorization` / `bearer` |
| [OpenAI](openai/) | `api.openai.com/v1/*` | `env://OPENAI_API_KEY` | `Authorization` / `bearer` |
| [OpenCode](opencode/) | `opencode.ai/zen/v1/*` (Zen) · `/zen/go/v1/*` (Go) | `env://OPENCODE_API_KEY` | `Authorization` / `bearer` |
| [OpenRouter](openrouter/) | `openrouter.ai/api/v1/*` | `env://OPENROUTER_API_KEY` | `Authorization` / `bearer` |
| [OVHcloud](ovhcloud/) | `oai.endpoints.kepler.ai.cloud.ovh.net/v1/*` | `env://OVHCLOUD_API_KEY` | `Authorization` / `bearer` |
| [Perplexity](perplexity/) | `api.perplexity.ai/v1/*` | `env://PERPLEXITY_API_KEY` | `Authorization` / `bearer` |
| [StepFun](stepfun-ai/) | `api.stepfun.ai/v1/*` | `env://STEPFUN_API_KEY` | `Authorization` / `bearer` |
| [Tencent](tencent/) | `api.lkeap.cloud.tencent.com/coding/v3/*` | `env://TENCENT_CODING_PLAN_API_KEY` | `Authorization` / `bearer` |
| [TokenRouter](tokenrouter/) | `api.tokenrouter.com/v1/*` | `env://TOKENROUTER_API_KEY` | `Authorization` / `bearer` |
| [Together AI](togetherai/) | `api.together.xyz/v1/*` | `env://TOGETHER_API_KEY` | `Authorization` / `bearer` |
| [Venice](venice/) | `api.venice.ai/api/v1/*` | `env://VENICE_API_KEY` | `Authorization` / `bearer` |
| [xAI](xai/) | `api.x.ai/v1/*` | `env://XAI_API_KEY` | `Authorization` / `bearer` |
| [Xiaomi (MiMo)](xiaomi/) | `api.xiaomimimo.com/v1/*` | `env://MIMO_API_KEY` | `Authorization` / `bearer` |
| [Z.AI](zai/) | `api.z.ai/api/paas/v4/*` · `/api/coding/paas/v4/*` | `env://ZHIPU_API_KEY` | `Authorization` / `bearer` |
| [ZhipuAI](zhipuai/) | `open.bigmodel.cn/api/paas/v4/*` | `env://ZHIPU_API_KEY` | `Authorization` / `bearer` |

Other secret sources exist than `env://` (`file://`, `sops://`, resolver
plugins) — these examples deliberately use `env://` only. See the full
reference: [`[secret]`](../../docs-site/docs/guide/configuration/secret.md)
and [injection](../../docs-site/docs/guide/secrets/injection.md).