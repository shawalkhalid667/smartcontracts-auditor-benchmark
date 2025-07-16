# tools/tool1/run.py

import sys
import os
from unsloth import FastLanguageModel
import torch


# code was taken from the colab notebook at 
# https://colab.research.google.com/drive/1Y_SHymcZGr98832GTSF46J1_JHtHgYhy?usp=sharing#scrollTo=RPT2gV3PA8CU



max_seq_length = 2048
dtype = None
load_in_4bit = True

model_name = "weifar/FTAudit-Llama3-8b-v1.0"
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name = model_name,
    max_seq_length = max_seq_length,
    dtype = dtype,
    load_in_4bit = load_in_4bit,
)

pymodel = FastLanguageModel.get_peft_model(
    model,
    r = 16, # Choose any number > 0 ! Suggested 8, 16, 32, 64, 128
    target_modules = ["q_proj", "k_proj", "v_proj", "o_proj",
                      "gate_proj", "up_proj", "down_proj",],
    lora_alpha = 16,
    lora_dropout = 0, # Supports any, but = 0 is optimized
    bias = "none",    # Supports any, but = "none" is optimized
    # [NEW] "unsloth" uses 30% less VRAM, fits 2x larger batch sizes!
    use_gradient_checkpointing = "unsloth", # True or "unsloth" for very long context
    random_state = 3407,
    use_rslora = False,  # We support rank stabilized LoRA
    loftq_config = None, # And LoftQ
)

# 0 is file, 1 is gpu, 2 is contract, 3 is prompt
prompt_file_name = os.path.join("/app", "prompts", sys.argv[2])
prompt_file = open(prompt_file_name)

contract_file_name = os.path.join("/app", "datasets", "textCode",  sys.argv[1])
contract_file = open(contract_file_name)

pre_prompt = prompt_file.read()
contract = contract_file.read()

pre_prompt += contract 

pre_prompt += "\n\n### Response:\n"

FastLanguageModel.for_inference(model)

inputs = tokenizer(pre_prompt, return_tensors = "pt")



outputs = model.generate(**inputs, max_new_tokens = 1000, use_cache = True)
outputs_decoded = tokenizer.batch_decode(outputs)
print(outputs_decoded)

