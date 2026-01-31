import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL_PATH = "base_wo_mu"

def load_model():
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_PATH,
        torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
    )
    model.eval()
    return tokenizer, model

def run_dummy_prompt():
    tokenizer, model = load_model()

    prompt = (
        "You are a smart contract security auditor. "
        "Analyze the following Solidity contract and list any vulnerabilities.\n\n"
        "// Simple test contract\n"
        "pragma solidity ^0.8.0;\n"
        "contract Test {\n"
        "    uint256 public balance;\n"
        "    function set(uint256 x) public {\n"
        "        balance = x;\n"
        "    }\n"
        "}\n\n"
        "Analysis:"
    )

    inputs = tokenizer(prompt, return_tensors="pt")
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=256,
            do_sample=False
        )

    text = tokenizer.decode(outputs[0], skip_special_tokens=True)
    print(text)

if __name__ == "__main__":
    run_dummy_prompt()

