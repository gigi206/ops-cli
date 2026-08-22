# Secrets — injecting credentials without letting them into the cage

One provider per subdirectory, each carrying what is specific to it: the host, the
variable, why you would want it, and how to verify against *that* service. What they
all share is not repeated here, it is linked below.

## The mechanics live in the guide

Everything these recipes share — the never-in-cage invariant, the shape of a `[secret]`
block, the `bearer`/`basic`/`raw` value types, the filtering posture injection needs,
what happens when a source produces nothing, and how to scope a declaration to one app
— is documented once, in the guide:

- **[Secrets](https://gigi206.github.io/ops-cli/docs/secrets/)** — the model: resolver ×
  broker, and what the invariant does and does not cover.
- **[`[secret]`](https://gigi206.github.io/ops-cli/docs/configuration/secret)** — the
  field reference: every key of the block below.
- **[Give an agent a credential it can use but never read](https://gigi206.github.io/ops-cli/docs/how-to/inject-a-credential)**
  — the same six steps as these recipes, walked once end to end.

The block every page here declares:

```toml
[secret."<host>"]
from   = "env://<VARIABLE_NAME>"   # resolved host-side; never inside the cage
header = "Authorization"           # the header the proxy sets on the request
type   = "bearer"                  # bearer | basic | raw
```

Two things worth repeating because a recipe fails silently without them: injection is
done by the egress proxy, so the cage needs a **filtering posture** (`deny`/`allow`/`ask`)
whose allowlist reaches the host; and a credential belongs in `[secret]`, never in
`[env]`, which *is* visible inside the cage.

These examples deliberately use `env://` only. `file://`, `sops://` and the resolver
plugins are in [Resolvers](https://gigi206.github.io/ops-cli/docs/secrets/resolvers).

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

Each page above is published as well, under
[Provider recipes](https://gigi206.github.io/ops-cli/docs/secrets/providers/): the site
generates that section from these files, so the two never disagree.