import json
import re
import os
from transformers import AutoTokenizer, AutoModelForCausalLM
from datetime import datetime
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# 模型路径
model_path = "Smart-LLaMA-DPO/model/base_wo_mu"

tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
model = AutoModelForCausalLM.from_pretrained(model_path, trust_remote_code=True, device_map="auto")

# 读取JSONL文件
data_path = "Smart-LLaMA-DPO/data/eval/for_detection/eval_timestamp.jsonl"

with open(data_path, "r", encoding="utf-8") as f:
    data = [json.loads(line) for line in f]

# 漏洞类型和对应的提示
vulnerability_prompts = {
    "reentrancy": "Analyze the smart contract for reentrancy vulnerabilities.",
    "timestamp_dependence": "Analyze the smart contract for timestamp dependence vulnerabilities.",
    "delegatecall": "Analyze the smart contract for delegatecall vulnerabilities.",
    "integer_overflow_underflow": "Analyze the smart contract for integer overflow or underflow vulnerabilities."
}

# 指定要分析的漏洞类型
vulnerabilities_to_analyze = ["timestamp_dependence"]

# 从模型路径中提取有意义的部分
model_identifier = os.path.basename(os.path.dirname(model_path))
checkpoint = os.path.basename(model_path)
model_name = f"{model_identifier}-{checkpoint}"

# 从数据路径中提取文件名
data_filename = os.path.basename(data_path)
data_identifier = os.path.splitext(data_filename)[0]  # 移除文件扩展名

# 创建输出文件
output_files = {vuln_type: f"{model_name}_{data_identifier}_{datetime.now().strftime('%Y%m%d-%H%M')}.txt" for vuln_type in vulnerabilities_to_analyze}

def print_and_write(message, vuln_type):
    print(message)
    with open(output_files[vuln_type], "a", encoding="utf-8") as f:
        f.write(message + "\n")

def remove_duplicates(text):
    # 匹配从 "0. " 或 "1. " 开始，到下一个 "0. "、"1. " 或 "2. " 之前的内容，或者到文本结束
    pattern = r'([01]\.\s*.+?)(?=\s*[012]\.\s*|\Z)'
    matches = re.finditer(pattern, text, re.DOTALL | re.IGNORECASE)
    
    print("Original text:")
    print(text)
    print("\nMatched text:")

    for i, match in enumerate(matches):
        matched_text = match.group(1).strip()
        print(f"Match {i+1}:")
        print(matched_text)
        print("\n---\n")
        if i == 0:
            return matched_text  # 返回第一个匹配的段落

    print("No match found")
    return text.strip()

def analyze_contract(contract_code, vuln_type, prompt):
    full_prompt = f"""Analyze the following smart contract for {vuln_type} vulnerabilities:

{contract_code}

{prompt}

Respond with '1' if you detect the vulnerability, or '0' if the contract appears safe from this specific vulnerability."""
    
    messages = [
        {"role": "system", "content": "You are a smart contract security analyzer. Analyze the given contract for the specified vulnerability and respond with '1' for vulnerable or '0' for safe."},
        {"role": "user", "content": full_prompt}
    ]
    text = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True
    )
    model_inputs = tokenizer([text], return_tensors="pt").to("cuda:7")
    
    generated_ids = model.generate(
        model_inputs.input_ids,
        max_new_tokens=512,
        do_sample=False,
        num_beams=1,
        temperature=0.0
    )
    generated_ids = [
        output_ids[len(input_ids):] for input_ids, output_ids in zip(model_inputs.input_ids, generated_ids)
    ]

    response = tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
    deduped_response = remove_duplicates(response)
    
    match = re.search(r'\b([01])\b', deduped_response)
    if match:
        return match.group(1), deduped_response
    else:
        return "invalid", deduped_response

results = {vuln_type: {"y_true": [], "y_pred": []} for vuln_type in vulnerabilities_to_analyze}

for vuln_type in vulnerabilities_to_analyze:
    print_and_write(f"Vulnerability Detections for {vuln_type}:\n", vuln_type)

for idx, item in enumerate(data):
    contract_code = item["contract"]
    expect_answer = item["target"]
    
    for vuln_type in vulnerabilities_to_analyze:
        prompt = vulnerability_prompts[vuln_type]
        actual_answer, full_response = analyze_contract(contract_code, vuln_type, prompt)
        
        results[vuln_type]["y_true"].append(int(expect_answer))
        results[vuln_type]["y_pred"].append(int(actual_answer) if actual_answer in ['0', '1'] else 0)
        
        print_and_write(f"\nContract {idx + 1}:", vuln_type)
        print_and_write(f"Contract code (first 100 characters): {contract_code[:100]}...", vuln_type)
        print_and_write(f"Expected: {expect_answer}", vuln_type)
        print_and_write(f"Actual: {actual_answer}", vuln_type)
        print_and_write(f"Full response: {full_response}", vuln_type)
        print_and_write("---", vuln_type)

    if (idx + 1) % 10 == 0:
        print(f"Processed {idx + 1} contracts")

for vuln_type in vulnerabilities_to_analyze:
    y_true = results[vuln_type]["y_true"]
    y_pred = results[vuln_type]["y_pred"]
    
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    auc = roc_auc_score(y_true, y_pred)
    
    print_and_write(f"\nFinal Results for {vuln_type}:", vuln_type)
    print_and_write(f"Total samples: {len(y_true)}", vuln_type)
    print_and_write(f"Accuracy: {accuracy:.4f}", vuln_type)
    print_and_write(f"Precision: {precision:.4f}", vuln_type)
    print_and_write(f"Recall: {recall:.4f}", vuln_type)
    print_and_write(f"F1 Score: {f1:.4f}", vuln_type)
    print_and_write(f"AUC: {auc:.4f}", vuln_type)

    print(f"\nResults for {vuln_type} have been saved to {output_files[vuln_type]}")

print("\nAnalysis complete.")