import os
import json
import re
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
from collections import defaultdict

# 初始化LLaMA模型
model_path = "/gemini/platform/public/llm/huggingface/Llama/meta-llama-3.1-70b-instruct"

tokenizer = AutoTokenizer.from_pretrained(model_path)
model = AutoModelForCausalLM.from_pretrained(model_path, device_map="auto", torch_dtype=torch.float16)

def read_jsonl_file(file_path):
    try:
        with open(file_path, 'r') as file:
            data = [json.loads(line) for line in file]
        print(f"Successfully read {len(data)} lines from JSONL file.")
        return data
    except Exception as e:
        print(f"Error reading JSONL file: {e}")
        return []

def read_explanation_file(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
        print(f"Successfully read explanation file: {file_path}")
        return content
    except Exception as e:
        print(f"Error reading explanation file {file_path}: {e}")
        return ""

def parse_explanation(content):
    pattern = r'Full response: (\d)\. (.*?)(?=---|\Z)'
    explanations = re.findall(pattern, content, re.DOTALL)
    print(f"Parsed {len(explanations)} explanations from the content.")
    return explanations

def evaluate_reentrancy_explanation(explanation, contract_code, true_label, predicted_label):
    prompt = f"""
    Evaluate the following smart contract reentrancy vulnerability explanation based on correctness, completeness, and conciseness. Use a 4-point Likert scale for each dimension:

    1 - Disagree
    2 - Somewhat disagree
    3 - Somewhat agree
    4 - Agree

    Contract code:
    {contract_code}

    True reentrancy vulnerability label: {true_label} (0 means no vulnerability, 1 means vulnerable)
    Predicted reentrancy vulnerability label: {predicted_label} (0 means no vulnerability, 1 means vulnerable)

    Explanation to evaluate:
    {explanation}

    Provide your evaluation in the following format:
    Correctness: [score]
    Rationale: [your rationale]

    Completeness: [score]
    Rationale: [your rationale]

    Conciseness: [score]
    Rationale: [your rationale]

    Overall assessment: [brief overall assessment focusing on reentrancy vulnerability detection and the accuracy of the prediction]
    """

    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    with torch.no_grad():
        outputs = model.generate(**inputs, max_length=1500)
    evaluation = tokenizer.decode(outputs[0], skip_special_tokens=True)

    return evaluation

def extract_scores(evaluation):
    scores = {}
    for dimension in ['Correctness', 'Completeness', 'Conciseness']:
        match = re.search(f"{dimension}: (\d)", evaluation)
        if match:
            scores[dimension.lower()] = int(match.group(1))
    return scores

def save_results(results, score_stats, prediction_stats, processed_files, matched_files, output_file):
    with open(output_file, 'w') as f:
        json.dump({
            'results': results,
            'score_statistics': dict(score_stats),
            'prediction_statistics': prediction_stats,
            'processed_files': processed_files,
            'matched_files': matched_files
        }, f, indent=2)
    print(f"Results saved to {output_file}")

def print_statistics(score_stats, prediction_stats):
    print("\nCurrent Score Statistics:")
    for dimension, scores in score_stats.items():
        print(f"\n{dimension.capitalize()}:")
        for score in range(1, 5):
            print(f"  {score} points: {scores[score]} evaluations")

    print("\nCurrent Prediction Statistics:")
    total = prediction_stats["correct"] + prediction_stats["incorrect"]
    if total > 0:
        print(f"  Correct predictions: {prediction_stats['correct']} ({prediction_stats['correct']/total*100:.2f}%)")
        print(f"  Incorrect predictions: {prediction_stats['incorrect']} ({prediction_stats['incorrect']/total*100:.2f}%)")
    else:
        print("  No predictions were made.")

def process_reentrancy_files(explanation_dir, jsonl_file, output_file, evaluation_txt_file):
    jsonl_data = read_jsonl_file(jsonl_file)
    if not jsonl_data:
        print("No data found in JSONL file. Exiting.")
        return

    results = []
    score_stats = defaultdict(lambda: defaultdict(int))
    prediction_stats = {"correct": 0, "incorrect": 0}
    processed_files = 0
    matched_files = 0

    explanation_files = sorted([f for f in os.listdir(explanation_dir) if f.endswith('.txt')])
    print(f"Found {len(explanation_files)} explanation files.")

    with open(evaluation_txt_file, 'w', encoding='utf-8') as eval_file:
        for filename in explanation_files:
            processed_files += 1
            file_path = os.path.join(explanation_dir, filename)
            content = read_explanation_file(file_path)
            if not content:
                print(f"Skipping empty file: {filename}")
                continue

            explanations = parse_explanation(content)
            if not explanations:
                print(f"No explanations found in file: {filename}")
                continue

            matched_files += 1

            for idx, (predicted_label, explanation) in enumerate(explanations):
                if idx >= len(jsonl_data):
                    print(f"Warning: More explanations than JSONL entries. Stopping at index {idx}.")
                    break

                contract_data = jsonl_data[idx]
                contract_code = contract_data['contract']
                true_label = contract_data['target']

                print(f"\nProcessing explanation {idx+1}/{len(explanations)} from file {filename}")
                print(f"True label: {true_label}, Predicted label: {predicted_label}")
                
                evaluation = evaluate_reentrancy_explanation(explanation, contract_code, true_label, predicted_label)
                scores = extract_scores(evaluation)
                
                for dimension, score in scores.items():
                    score_stats[dimension][score] += 1

                if int(predicted_label) == int(true_label):
                    prediction_stats["correct"] += 1
                else:
                    prediction_stats["incorrect"] += 1

                result = {
                    'file': filename,
                    'contract_code': contract_code,
                    'true_reentrancy_label': true_label,
                    'predicted_reentrancy_label': predicted_label,
                    'reentrancy_explanation': explanation,
                    'evaluation': evaluation,
                    'scores': scores
                }
                results.append(result)

                # 输出当前处理的结果
                print(f"Evaluation scores: {scores}")
                print(f"Prediction: {'Correct' if int(predicted_label) == int(true_label) else 'Incorrect'}")
                print("Evaluation:")
                print(evaluation)

                # 将评估结果写入txt文件
                eval_file.write(f"File: {filename}\n")
                eval_file.write(f"Explanation {idx+1}/{len(explanations)}\n")
                eval_file.write(f"True label: {true_label}, Predicted label: {predicted_label}\n")
                eval_file.write("Contract code:\n")
                eval_file.write(f"{contract_code}\n\n")
                eval_file.write("Explanation:\n")
                eval_file.write(f"{explanation}\n\n")
                eval_file.write("Evaluation:\n")
                eval_file.write(f"{evaluation}\n")
                eval_file.write(f"Evaluation scores: {scores}\n")
                eval_file.write(f"Prediction: {'Correct' if int(predicted_label) == int(true_label) else 'Incorrect'}\n")
                eval_file.write("-" * 80 + "\n\n")

                # 每处理 10 个解释就保存一次结果
                if len(results) % 10 == 0:
                    save_results(results, score_stats, prediction_stats, processed_files, matched_files, output_file)

            print(f"Processed file {processed_files}/{len(explanation_files)}: {filename}")

    # 最后保存一次完整结果
    save_results(results, score_stats, prediction_stats, processed_files, matched_files, output_file)

    print(f"\nProcessed {processed_files} files, matched {matched_files} contracts.")
    print_statistics(score_stats, prediction_stats)
    print(f"Evaluation details saved to {evaluation_txt_file}")


explanation_dir = 'Smart_LLaMA-DPO/evaluation/artifacts/final_results/reentrancy/'
jsonl_file = 'Smart_LLaMA-DPO/data/eval/eval_reentrancy.jsonl'
output_file = 'reentrancy_evaluation_results.json'
evaluation_txt_file = 'reentrancy_evaluation_details.txt'
process_reentrancy_files(explanation_dir, jsonl_file, output_file, evaluation_txt_file)