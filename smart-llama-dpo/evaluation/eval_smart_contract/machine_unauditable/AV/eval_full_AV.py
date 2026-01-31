import json
import re
import os
from transformers import AutoTokenizer, AutoModelForCausalLM
from datetime import datetime
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# Model path
model_path = "Smart-LLaMA-DPO/model/base"

tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
model = AutoModelForCausalLM.from_pretrained(model_path, trust_remote_code=True, device_map="auto")

# Read JSONL file
data_path = "Smart-LLaMA-DPO/data/eval/for_detection/eval_AV.jsonl"

with open(data_path, "r", encoding="utf-8") as f:
    data = [json.loads(line) for line in f]

# Vulnerability types and corresponding prompts
vulnerability_prompts = {
    "price_oracle": "Analyze the smart contract for price oracle manipulation vulnerabilities. Provide a detailed explanation of your analysis, including any potential vulnerabilities found or why the contract is safe. After your explanation, conclude with '1' if you detect a vulnerability, or '0' if the contract appears safe.",
    "erroneous_accounting": "Analyze the smart contract for erroneous accounting vulnerabilities.",
    "id_uniqueness": "Analyze the smart contract for ID uniqueness violation vulnerabilities.",
    "inconsistent_state": "Analyze the smart contract for inconsistent state update vulnerabilities.",
    "privilege_escalation": "Analyze the smart contract for privilege escalation vulnerabilities.",
    "atomicity_violations": "Analyze the smart contract for atomicity violation vulnerabilities.",
    "contract_implementation": "Analyze the smart contract for contract implementation specific vulnerabilities."
}

# Specify the vulnerabilities to analyze - only analyze price_oracle
vulnerabilities_to_analyze = ["atomicity_violations"]

# Extract meaningful parts from the model path
model_identifier = os.path.basename(os.path.dirname(model_path))
checkpoint = os.path.basename(model_path)
model_name = f"{model_identifier}-{checkpoint}"

# Extract filename from data path
data_filename = os.path.basename(data_path)
data_identifier = os.path.splitext(data_filename)[0]  # Remove file extension

# Create output files
output_files = {vuln_type: f"{model_name}_{data_identifier}_{datetime.now().strftime('%Y%m%d-%H%M')}.txt" for vuln_type in vulnerabilities_to_analyze}

def print_and_write(message, vuln_type):
    print(message)
    with open(output_files[vuln_type], "a", encoding="utf-8") as f:
        f.write(message + "\n")

def verify_answer(expect: str, actual: str) -> bool:
    return expect.strip() == actual.strip()

def analyze_contract(contract_code, vuln_type, prompt):
    full_prompt = f"""Analyze the following smart contract for {vuln_type} vulnerabilities:

{contract_code}

{prompt}"""
    
    messages = [
        {"role": "system", "content": "You are a smart contract security analyzer. Analyze the given contract for the specified vulnerability. Provide a detailed explanation of your analysis, and conclude with '1' for vulnerable or '0' for safe."},
        {"role": "user", "content": full_prompt}
    ]
    text = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True
    )
    model_inputs = tokenizer([text], return_tensors="pt").to("cuda:7")
    
    # Use greedy decoding with increased max_new_tokens
    generated_ids = model.generate(
        model_inputs.input_ids,
        max_new_tokens=2048,  # Increased from 512 to allow longer explanations
        do_sample=False,
        num_beams=1,
        temperature=0.0
    )
    generated_ids = [
        output_ids[len(input_ids):] for input_ids, output_ids in zip(model_inputs.input_ids, generated_ids)
    ]

    response = tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]
    
    # Extract the final binary prediction
    match = re.search(r'([01])\s*$', response.strip())
    if match:
        prediction = match.group(1)
    else:
        # If no clear binary prediction at the end, search for any binary prediction in the text
        match = re.search(r'\b([01])\b', response)
        prediction = match.group(1) if match else "invalid"
    
    return prediction, response

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
        print_and_write(f"Contract code:", vuln_type)
        print_and_write(contract_code, vuln_type)
        print_and_write(f"\nExpected: {expect_answer}", vuln_type)
        print_and_write(f"Actual: {actual_answer}", vuln_type)
        print_and_write(f"Full analysis:", vuln_type)
        print_and_write(full_response, vuln_type)
        print_and_write("\n" + "="*80 + "\n", vuln_type)

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