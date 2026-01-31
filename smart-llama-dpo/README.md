# Smart-LLaMA-DPO

Smart-LLaMA-DPO is an advanced smart contract vulnerability detection and explanation system built upon the LLaMA-3.1-8B model. The system addresses key challenges in smart contract security using a comprehensive approach that combines Continual Pre-training (CPT), Supervised Fine-tuning (SFT), and Direct Preference Optimization (DPO). This ensures enhanced performance in identifying vulnerabilities and generating high-quality explanations for detected issues.

## Project Structure

```
Smart-LLaMA-DPO/
├── data/                               # Dataset directory
│   ├── cpt/                            # Continual Pre-Training (CPT) data
│   ├── dpo/                            # Direct Preference Optimization (DPO) data
│   ├── eval/                           # Evaluation data
│   │   ├── for_detection/              # Datasets for vulnerability detection evaluation
│   │   └── for_explanation             # Datasets for explanation evaluation
│   └── sft/                            # Supervised Fine-Tuning (SFT) data
├── evaluation/                         # Evaluation scripts and results
│   ├── artifacts/
│   │   ├── ablation_study/             # Ablation study results
│   │   ├── baseline/                   # Baseline model results
│   │   └── final_results/              # Final evaluation results
│   ├── eval_smart_contract/
│   │   ├── delegatecall/               # Eval scripts for delegatecall
│   │   ├── integer_overflow_underflow/ # Eval scripts for integer_overflow_underflow
│   │   ├── machine_unauditable/        # Eval scripts for machine_unauditable
│   │   │   └── AV/                     
│   │   │   └── CI/                     
│   │   │   └── EA/
│   │   │   └── IS/
│   │   │   └── IU/
│   │   │   └── PE/
│   │   │   └── PO/
│   │   ├── reentrancy/                 # Eval scripts for reentrancy
│   │   └── timestamp/                  # Eval scripts for timestamp
│   └── explain_evaluation/
│       ├── baseline_artifacts/         # Baseline explanation results
│       ├── smart_llama_artifacts/      # Smart-LLaMA explanation results
│       ├── LLM_evaluate_delegatecall.py
│       ├── LLM_evaluate_integer.py
│       ├── LLM_evaluate_reentrancy.py
│       └── LLM_evaluate_timestamp.py
└── model/                              # Model weights and configurations
│   ├── base/                           # Full model configurations
│   ├── wo_cpt/                         # Model without CPT
│   ├── wo_dpo/                         # Model without DPO
│   ├── wo_cpt&&dpo/                    # Model without CPT and DPO
└── training/                           # Training scripts and configurations
│   ├── CPT/                            # Scripts for Continual Pre-Training (CPT)
│   ├── DPO/                            # Scripts for Direct Preference Optimization (DPO)
│   ├── SFT/                            # Scripts for Supervised Fine-Tuning (SFT)
│   ├── LLaMA-Factory/                  # Source code for LLaMA-Factory
```

## Getting Started

This guide will help you quickly set up and run a simple demonstration of the Smart-LLaMA-DPO smart contract vulnerability detection system.

## Artifacts

All evaluation artifacts and supplementary materials (including evaluation scripts, generated outputs, and documentation) for artifact evaluation are also available at Zenodo:

[Smart-LLaMA-DPO Artifacts](https://zenodo.org/records/15201991)

> **Artifact badges:**  
> - **Artifact Available**: All necessary materials are publicly accessible.  
> - **Artifact Functional**: All main claims and results in the paper are supported by the provided artifact and can be reproduced following the documentation.

### Clone Repository

To properly clone this repository with the included LLaMA-Factory submodule, use the following command:

```bash
# Clone with submodules
git clone --recurse-submodules https://gitlab.com/programmer-of-nansijie/smart-llama-dpo.git

# If you've already cloned without submodules, run:
git submodule update --init --recursive
```

### Model Weights

The trained model weights for Smart-LLaMA-DPO can be downloaded from our Zenodo repository:
- [Smart-LLaMA-DPO Model Weights](https://zenodo.org/records/15255329)

Download the model weights and place them in the appropriate directory under `model/` before running the evaluation scripts.

To reproduce results, modify key parameters: for the four main vulnerability types (reentrancy, integer_overflow_underflow, delegatecall, timestamp), use 'Smart-LLaMA-DPO/model/base_wo_mu' as the model_path; for machine-unauditable vulnerabilities, use 'Smart-LLaMA-DPO/model/base' as the model_path and set the appropriate data_path.

**Note**: Since the models published here have been retrained using desensitized data to protect privacy and intellectual property (the original training data contained content from private GitHub repositories), some results may differ from those reported in the paper.

### System Requirements for Inference

Hardware: GPU with at least 16GB VRAM (24GB+ recommended)
OS: Ubuntu 20.04 LTS or newer (tested on Ubuntu 22.04 LTS)
Python: Python 3.10 or newer
CUDA: CUDA 11.8 or newer

### Setup Instructions

1. Install required dependencies:
   
   ```bash
   pip install transformers torch scikit-learn
   ```

2. Quick Demonstration (Estimated time: 10 minutes)
   We've prepared a script that will detect reentrancy vulnerabilities in smart contracts.
- `Navigate to the getting_started directory`: 
  
  ```bash
  cd evaluation/getting_started
  ```

- `Run the demonstration script`: 
  
  ```bash
  python eval_reentrancy_full_reduplicate.py
  ```

This script will:

- `Load the Smart-LLaMA-DPO model from ../../model/base_wo_mu`

- `Analyze smart contracts from eval_reentrancy_small.jsonl for reentrancy vulnerabilities`

- `Generate detection results with evaluation metrics`

- `Save results to a timestamped output file`
3. Expected output:
   The script will display contract-by-contract analysis and produce a summary of results including:
   Accuracy, Precision, Recall, F1 Score, and AUC metrics
   Detailed responses for each analyzed contract
   A timestamped output file with all results

4. Input data:
   The test samples are stored in eval_reentrancy_small.jsonl, which contains smart contracts with known vulnerability status.

## Datasets

- `data/cpt/`: Contains data for Continual Pre-training (CPT), used for domain adaptation and improving the model’s understanding of smart contract data.
- `data/dpo/`: Contains training data for Direct Preference Optimization (DPO), which refines the model’s ability to generate user-preferred outputs.
- `data/eval/for_detection/`: Data for evaluating vulnerability detection.
- `data/eval/for_explanation/`: Data for evaluating explanation quality.
- `data/sft/`: Contains data for Supervised Fine-Tuning (SFT), which trains the model on specific vulnerability detection tasks.

**Note**: All datasets included in this repository have been desensitized to protect privacy and intellectual property. The original training data contained content from private GitHub repositories, and we have processed the data to remove sensitive information while preserving the functionality for smart contract vulnerability detection research.

## Evaluation

The evaluation is divided into two main parts:

1. Vulnerability Detection Evaluation (`eval_smart_contract/`):
   
   - Evaluates four main types of vulnerabilities: delegatecall, integer overflow/underflow, reentrancy, and timestamp dependency.
   - Evaluates seven Machine-Unauditable Vulnerabilities (MU): Price Oracle Manipulation, Erroneous Accounting, ID Uniqueness Violations, Inconsistent State Updates, Privilege Escalation, Atomicity Violations, and Contract Implementation Specific vulnerabilities.

2. Explanation Quality Evaluation (`explain_evaluation/`):
   
   - Uses Large Language Models (LLMs) to evaluate the quality of generated explanations.
   - Includes evaluation of explanations generated by both baseline and Smart_LLaMA models.

## Models

The project includes multiple model configurations stored in the model/ directory:

- `Base Model`:
  The full version of the model trained using CPT, SFT, and DPO.

- `Ablation Models`:

  Variants of the model trained without certain components:

  wo_cpt/: Without Continual Pre-Training (CPT).

  wo_dpo/: Without Direct Preference Optimization (DPO).
  
  wo_cpt&dpo/: Without both CPT and DPO.

## Usage

### Running Vulnerability Detection

#### For delegatecall vulnerability detection

```bash
cd Smart-LLaMA-DPO/evaluation/eval_smart_contract/delegatecall
python eval_delegatecall_full_reduplicate.py
```

#### For reentrancy vulnerability detection

```bash
cd Smart-LLaMA-DPO/evaluation/eval_smart_contract/reentrancy
python eval_reentrancy_full_reduplicate.py
```

### Evaluating Explanation Quality

```bash
cd Smart_LLaMA-DPO/evaluation/explain_evaluation
python LLM_evaluate_reentrancy.py
```

## Training

### Clone Repository

The latest version of LLaMA-Factory can be obtained from https://github.com/hiyouga/LLaMA-Factory 

To properly clone this repository with the included LLaMA-Factory submodule, use the following command:

```bash
# Clone with submodules
git clone --recurse-submodules https://gitlab.com/programmer-of-nansijie/smart-llama-dpo.git

# If you've already cloned without submodules, run:
git submodule update --init --recursive
```

### Training Environment Setting
```bash
cd training/LLaMA-Factory/
pip install -e ".[torch,metrics]"
```

### System Requirements for Training

Hardware: 8x NVIDIA H800 GPUs (80GB VRAM each)
OS: Ubuntu 20.04 LTS or newer (tested on Ubuntu 22.04 LTS)
Python: Python 3.10 or newer
CUDA: CUDA 11.8 or newer

### Continual Pre-Training

```bash
cd Smart_LLaMA-DPO/training/CPT
bash single_node_llama3.1.sh
```

### Superivesed Fine-Tuning

```bash
cd Smart_LLaMA-DPO/training/SFT
bash single_node_llama3.1.sh
```

### Direct Preference Optimization

```bash
cd Smart_LLaMA-DPO/training/DPO
bash single_node_llama3.1.sh
```

## Extension Guide: Adding New Smart Contract Vulnerability Types
This guide explains how to extend the Smart-LLaMA-DPO framework to support new types of smart contract vulnerabilities beyond those discussed in the original paper.

### 1. Preparing Data for a New Vulnerability Type
#### 1.1 Dataset Structure

Add data for the new vulnerability type following the existing directory structure:
```
data/
├── cpt/              # Continual Pre-Training data
├── sft/              # Supervised Fine-Tuning data
│   └── new_vulnerability_type.jsonl
├── dpo/              # Direct Preference Optimization data
│   └── new_vulnerability_type.jsonl
└── eval/
    └── for_detection/
        └── new_vulnerability_type.jsonl
```

#### 1.2 Data Format
Follow the existing data formats:

- `SFT data`: Contract code, vulnerability annotations, and explanations.
- `DPO data`: Contract code, high-quality responses, and low-quality responses.
- `Evaluation data`: Contract code and vulnerability status.

#### 1.3 Recommended Data Quantities

- `CPT data`: More than 100,000 relevant contract samples
- `SFT data`: More than 5000 annotated samples
- `DPO data`: More than 1000 preference pairs
- `Evaluation data`: At least 100 samples

### 2. Training Process

First, ensure you've cloned the repository with submodules as described in the Training section.

```bash
cd training/LLaMA-Factory/
pip install -e ".[torch,metrics]"
```

Follow the existing three-stage training process (CPT→SFT→DPO) using the LLaMA-Factory framework:

- `CPT`: Domain adaptation using smart contract data relevant to the new vulnerability type
- `SFT`: Supervised fine-tuning using annotated data
- `DPO`: Direct preference optimization using preference data

Simply copy the existing training scripts and modify the data paths and ouput model paths.

### 3. Evaluating the New Vulnerability Type
Reuse the existing evaluation framework:

Create a subdirectory for the new vulnerability type in evaluation/eval_smart_contract/

Copy an existing evaluation script (e.g., eval_reentrancy_full_reduplicate.py) and rename it

Modify the data paths and prompt templates in the script to fit the new vulnerability type

### 4. Training Tips
- `Data Quality`: Ensure balance between positive and negative samples, and cover various manifestations of the vulnerability
- `Learning Rate`: Use a consistent learning rate of 1e-5 across all training stages (CPT, SFT, and DPO) as per the project's configuration
- `Training Stability`: Use gradient accumulation and checkpointing to maintain training stability

By following this guide, the Smart-LLaMA-DPO framework can be flexibly extended to new smart contract vulnerability types without modifying the core framework structure.