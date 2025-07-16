import sys
import os
import subprocess
import torch

device = torch.device("cpu")
model_name = "weifar/FTAudit-Llama3-8b-v1.0"

# Try importing bitsandbytes-cpu and installing if necessary
try:
    import intel_extension_for_pytorch as ipex
    from transformers import BitsAndBytesConfig
except ImportError:
    print("BitsAndBytesConfig not found. Installing bitsandbytes-cpu + dependencies...")
    subprocess.run(["pip", "install", "--no-cache-dir", "intel-extension-for-pytorch", "oneccl_bind_pt", "--extra-index-url", "https://pytorch-extension.intel.com/release-whl/stable/cpu/us/", "bitsandbytes"], check=True)
    import intel_extension_for_pytorch as ipex
    from transformers import BitsAndBytesConfig


from transformers import AutoTokenizer, AutoModelForCausalLM # imported down here b/c ipex docs recommend ipex is imported right after torch, before other imports


# Try to load model with quantization
try:
    print("Trying to load quantized model on CPU...")
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_use_double_quant=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float32,  # CPU only supports float32
    )
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        quantization_config=bnb_config,
        device_map={"": device},
    )
except Exception as e:
    print(f"Quantized loading failed. Falling back to normal model loading. Reason:\n{e}")
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        device_map={"": "cpu"},
        ignore_mismatched_sizes=True,
        low_cpu_mem_usage=True,
        trust_remote_code=True,
        quantization_config=None  # <-- this disables built-in quant config
    ).to("cpu")

print("Now loading tokenizer")
# Load tokenizer
tokenizer = AutoTokenizer.from_pretrained(model_name)

# 0 = file, 1 = gpu flag (ignored), 2 = contract, 3 = prompt
contract_path = os.path.expanduser(os.path.join("/app", "datasets", "textCode", sys.argv[1]))
prompt_path   = os.path.expanduser(os.path.join("/app", "prompts", sys.argv[2]))

print("Now reading text files")
with open(prompt_path, "r", encoding="utf-8") as f:
    prompt_text = f.read()

with open(contract_path, "r", encoding="utf-8") as f:
    contract_text = f.read()

full_prompt = f"{prompt_text}\n{contract_text}\n\n### Response:\n"

print("Now tokenizing inputs")
inputs = tokenizer(full_prompt, return_tensors="pt", truncation=True).to(device)

print("Now generating a reply")
outputs = model.generate(**inputs, max_new_tokens=1000, do_sample=True, pad_token_id=tokenizer.eos_token_id)
print("Now decoding the reply")
output_text = tokenizer.decode(outputs[0], skip_special_tokens=True)


print("Now printing the reply:\n")
print(output_text)
