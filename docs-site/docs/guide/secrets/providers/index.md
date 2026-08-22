---
title: Provider recipes
sidebar_label: Provider recipes
description: A ready-made [secret] block for around forty API providers, each keyed by the host it authenticates to.
sidebar_position: 0
---

# Provider recipes

One page per provider: the `[secret]` block to paste, the environment variable the
`from` names, what is specific to that service, and a request that proves the header
arrived. The mechanics they share are on [Secrets](../) and in
[`[secret]`](../../configuration/secret); each page below adds only what its own
service needs.

New to this? [Give an agent a credential it can use but never
read](../../how-to/inject-a-credential) walks the whole path once, then these pages are
lookups.

| Provider | Host | Source | Header / type |
|---|---|---|---|
| [`alibaba`](alibaba) | `dashscope-intl.aliyuncs.com/compatible-mode/v1/*` | `env://DASHSCOPE_API_KEY` | `Authorization` / `bearer` |
| [`alibaba-cn`](alibaba-cn) | `dashscope.aliyuncs.com/compatible-mode/v1/*` | `env://DASHSCOPE_API_KEY` | `Authorization` / `bearer` |
| [`anthropic`](anthropic) | `api.anthropic.com/v1/*` | `env://ANTHROPIC_API_KEY` | `Authorization` / `bearer` |
| [`baseten`](baseten) | `inference.baseten.co/v1/*` | `env://BASETEN_API_KEY` | `Authorization` / `bearer` |
| [`bytedance`](bytedance) | `ark.cn-beijing.volces.com/api/v3/*` | `env://ARK_API_KEY` | `Authorization` / `bearer` |
| [`cerebras`](cerebras) | `api.cerebras.ai/v1/*` | `env://CEREBRAS_API_KEY` | `Authorization` / `bearer` |
| [`cloudflare`](cloudflare) | `api.cloudflare.com/client/v4/accounts/*/ai/v1/*` | `env://CLOUDFLARE_API_TOKEN` | `Authorization` / `bearer` |
| [`cohere`](cohere) | `api.cohere.com/v2/*` | `env://COHERE_API_KEY` | `Authorization` / `bearer` |
| [`deepinfra`](deepinfra) | `api.deepinfra.com/v1/*` | `env://DEEPINFRA_API_KEY` | `Authorization` / `bearer` |
| [`deepseek`](deepseek) | `api.deepseek.com/*` | `env://DEEPSEEK_API_KEY` | `Authorization` / `bearer` |
| [`fireworks-ai`](fireworks-ai) | `api.fireworks.ai/inference/v1/*` | `env://FIREWORKS_API_KEY` | `Authorization` / `bearer` |
| [`flux`](flux) | `api.bfl.ai/*` | `env://BFL_API_KEY` | `x-key` / `raw` |
| [`github`](github) | `api.github.com` | `env://GITHUB_TOKEN` | `Authorization` / `bearer` |
| [`github-copilot`](github-copilot) | `api.individual.githubcopilot.com/*` | `env://GITHUB_COPILOT_API_TOKEN` | `Authorization` / `bearer` |
| [`google`](google) | `generativelanguage.googleapis.com/v1beta/*` | `env://GEMINI_API_KEY` | `x-goog-api-key` / `raw` |
| [`groq`](groq) | `api.groq.com/openai/v1/*` | `env://GROQ_API_KEY` | `Authorization` / `bearer` |
| [`huggingface`](huggingface) | `router.huggingface.co/v1/*` | `env://HF_TOKEN` | `Authorization` / `bearer` |
| [`kilo`](kilo) | `api.kilo.ai/api/gateway/*` | `env://KILO_API_KEY` | `Authorization` / `bearer` |
| [`kimi`](kimi) | `api.kimi.com/coding/v1/*` | `env://KIMI_API_KEY` | `Authorization` / `bearer` |
| [`kling`](kling) | `api-singapore.klingai.com/*` | `env://KLINGAI_API_KEY` | `Authorization` / `bearer` |
| [`llama`](llama) | `api.llama.com/compat/v1/*` | `env://LLAMA_API_KEY` | `Authorization` / `bearer` |
| [`luma`](luma) | `api.lumalabs.ai/*` | `env://LUMA_API_KEY` | `Authorization` / `bearer` |
| [`meta-ai`](meta-ai) | `api.meta.ai/v1/*` | `env://MODEL_API_KEY` | `Authorization` / `bearer` |
| [`minimax`](minimax) | `api.minimax.io/v1/*` | `env://MINIMAX_API_KEY` | `Authorization` / `bearer` |
| [`mistral`](mistral) | `api.mistral.ai/v1/*` | `env://MISTRAL_API_KEY` | `Authorization` / `bearer` |
| [`moonshot`](moonshot) | `api.moonshot.ai/v1/*` | `env://MOONSHOT_API_KEY` | `Authorization` / `bearer` |
| [`nvidia`](nvidia) | `integrate.api.nvidia.com` | `env://NVIDIA_API_KEY` | `Authorization` / `bearer` |
| [`ollama`](ollama) | `ollama.com/v1/*` | `env://OLLAMA_API_KEY` | `Authorization` / `bearer` |
| [`openai`](openai) | `api.openai.com/v1/*` | `env://OPENAI_API_KEY` | `Authorization` / `bearer` |
| [`opencode`](opencode) | `opencode.ai/zen/v1/*` | `env://OPENCODE_API_KEY` | `Authorization` / `bearer` |
| [`openrouter`](openrouter) | `openrouter.ai/api/v1/*` | `env://OPENROUTER_API_KEY` | `Authorization` / `bearer` |
| [`ovhcloud`](ovhcloud) | `oai.endpoints.kepler.ai.cloud.ovh.net/v1/*` | `env://OVHCLOUD_API_KEY` | `Authorization` / `bearer` |
| [`perplexity`](perplexity) | `api.perplexity.ai/v1/*` | `env://PERPLEXITY_API_KEY` | `Authorization` / `bearer` |
| [`stepfun-ai`](stepfun-ai) | `api.stepfun.ai/v1/*` | `env://STEPFUN_API_KEY` | `Authorization` / `bearer` |
| [`tencent`](tencent) | `api.lkeap.cloud.tencent.com/coding/v3/*` | `env://TENCENT_CODING_PLAN_API_KEY` | `Authorization` / `bearer` |
| [`togetherai`](togetherai) | `api.together.xyz/v1/*` | `env://TOGETHER_API_KEY` | `Authorization` / `bearer` |
| [`tokenrouter`](tokenrouter) | `api.tokenrouter.com/v1/*` | `env://TOKENROUTER_API_KEY` | `Authorization` / `bearer` |
| [`venice`](venice) | `api.venice.ai/api/v1/*` | `env://VENICE_API_KEY` | `Authorization` / `bearer` |
| [`xai`](xai) | `api.x.ai/v1/*` | `env://XAI_API_KEY` | `Authorization` / `bearer` |
| [`xiaomi`](xiaomi) | `api.xiaomimimo.com/v1/*` | `env://MIMO_API_KEY` | `Authorization` / `bearer` |
| [`zai`](zai) | `api.z.ai/api/paas/v4/*` | `env://ZHIPU_API_KEY` | `Authorization` / `bearer` |
| [`zhipuai`](zhipuai) | `open.bigmodel.cn/api/paas/v4/*` | `env://ZHIPU_API_KEY` | `Authorization` / `bearer` |

Each page is generated from `examples/secrets/<name>/README.md`, which is the file
that sits beside the configuration it describes. Adding a provider there adds it here.
