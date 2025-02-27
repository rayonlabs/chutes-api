import json
import asyncio
from chutes.image import Image
from chutes.chute import NodeSelector
from chutes.chute.template.vllm import build_vllm_chute

image = (
    Image(username="test", name="vllm-custom", tag="0.6.3")
    .with_python("3.12.7")
    .apt_install(["google-perftools", "git"])
    .run_command("useradd vllm -s /sbin/nologin")
    .run_command("mkdir -p /app /home/vllm && chown vllm:vllm /app /home/vllm")
    .set_user("vllm")
    .set_workdir("/app")
    .with_env("PATH", "/opt/python/bin:/home/vllm/.local/bin:$PATH")
    .run_command("/opt/python/bin/pip install --no-cache 'vllm<0.6.4' wheel packaging")
    .run_command("/opt/python/bin/pip install --no-cache flash-attn")
    .run_command("/opt/python/bin/pip uninstall -y xformers")
)

chute = build_vllm_chute(
    username="test",
    model_name="unsloth/Llama-3.2-1B-Instruct",
    image=image,
    node_selector=NodeSelector(
        gpu_count=1,
    ),
)


async def main():
    request = {
        "json": {
            "model": "unsloth/Llama-3.2-1B-Instruct",
            "messages": [{"role": "user", "content": "Give me a spicy mayo recipe."}],
            "temperature": 0.7,
            "seed": 42,
            "max_tokens": 3,
            "stream": True,
            "logprobs": True,
        }
    }
    async for data in chute.chat_stream(**request):
        if not data:
            continue
        print(json.dumps(data, indent=2))

    print("*" * 80)
    request["json"].pop("stream")
    print(json.dumps(await chute.chat(**request), indent=2))


if __name__ == "__main__":
    asyncio.run(main())
