import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig

model_id = "weifar/FTAudit-gemma-7b-v1"

# Determine device
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
use_4bit = device.type == "cuda"  # Use 4-bit quantization only if CUDA is available

# Optional: log which device is being used
print(f"Using device: {device}")

# Configure bitsandbytes only if CUDA is available
bnb_config = BitsAndBytesConfig(
    load_in_4bit=use_4bit,
    bnb_4bit_use_double_quant=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16
) if use_4bit else None

# Load model with appropriate settings
model = AutoModelForCausalLM.from_pretrained(
    model_id,
    quantization_config=bnb_config if use_4bit else None,
    device_map="auto" if use_4bit else None,
    torch_dtype=torch.bfloat16 if use_4bit else torch.float32
).to(device)

# Load tokenizer
tokenizer = AutoTokenizer.from_pretrained(model_id, add_eos_token=True)

def get_completion(query: str, model, tokenizer) -> str:
    prompt_template = """
<start_of_turn>user
Below is an instruction that describes a task. Write a response that appropriately completes the request.
List all the vulnerabilities in the following solidity code of smart contract: 
{query}
<end_of_turn>
<start_of_turn>model
"""
    prompt = prompt_template.format(query=query)
    encodeds = tokenizer(prompt, return_tensors="pt", add_special_tokens=True).to(device)

    generated_ids = model.generate(
        **encodeds,
        max_new_tokens=8192,
        do_sample=True,
        pad_token_id=tokenizer.eos_token_id
    )
    decoded = tokenizer.decode(generated_ids[0], skip_special_tokens=True)
    return decoded

# Example query
query = '''pragma solidity ^0.4.23;

contract IntegerOverflowMultiTxOneFuncFeasible {
    uint256 private initialized = 0;
    uint256 public count = 1;

    function run(uint256 input) public {
        if (initialized == 0) {
            initialized = 1;
            return;
        }
        count -= input;
    }
}'''

# Run inference
result = get_completion(query=query, model=model, tokenizer=tokenizer)
print(result)
