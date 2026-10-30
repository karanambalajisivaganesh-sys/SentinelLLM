"""Evaluate SentinelLLM on a separately downloaded public dataset CSV.

Example (after downloading the public CSV):
  python evaluate_external_dataset.py path/to/prompt_injection_dataset.csv \
      --text-column prompt --label-column label --split-column split --test-value test

The evaluator does not train, tune the threshold, or change the model.
"""
import argparse, json
from pathlib import Path
import pandas as pd
import joblib
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
BASE=Path(__file__).resolve().parent

def to_label(value):
    s=str(value).strip().casefold()
    if s in {'1','attack','malicious','injection','true','yes','positive'}: return 1
    if s in {'0','benign','safe','false','no','negative'}: return 0
    raise ValueError(f'Unrecognized label {value!r}; map it to benign/attack or 0/1 first.')

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('csv',type=Path)
    ap.add_argument('--text-column',default='prompt')
    ap.add_argument('--label-column',default='label')
    ap.add_argument('--split-column',default='split')
    ap.add_argument('--test-value',default='test')
    ap.add_argument('--output',type=Path,default=BASE/'ml_models'/'external_benchmark_results.json')
    args=ap.parse_args()
    df=pd.read_csv(args.csv)
    if args.text_column not in df or args.label_column not in df: raise SystemExit(f'Missing columns. Found: {list(df.columns)}')
    if args.split_column in df and args.test_value:
        test=df[df[args.split_column].astype(str).str.casefold()==args.test_value.casefold()].copy()
    else:
        raise SystemExit('Refusing to score the full dataset without an explicit held-out split column. Provide --split-column and --test-value.')
    test=test.dropna(subset=[args.text_column,args.label_column]).copy()
    if test.empty: raise SystemExit('No test rows found. Check --split-column and --test-value.')
    test['mapped_label']=test[args.label_column].map(to_label)
    model=joblib.load(BASE/'ml_models'/'sentinelllm_tfidf_logreg.joblib')
    training=json.loads((BASE/'ml_models'/'training_metrics.json').read_text(encoding='utf-8'))
    threshold=float(training['threshold'])
    scores=model.predict_proba(test[args.text_column].astype(str).tolist())[:,1]
    pred=(scores>=threshold).astype(int)
    tn,fp,fn,tp=confusion_matrix(test.mapped_label,pred,labels=[0,1]).ravel()
    result={'dataset_path':str(args.csv),'test_rows':int(len(test)),'text_column':args.text_column,'label_column':args.label_column,'split_column':args.split_column,'test_value':args.test_value,'threshold_from_validation_only':threshold,'accuracy':float(accuracy_score(test.mapped_label,pred)),'precision_attack':float(precision_score(test.mapped_label,pred,zero_division=0)),'recall_attack':float(recall_score(test.mapped_label,pred,zero_division=0)),'f1_attack':float(f1_score(test.mapped_label,pred,zero_division=0)),'confusion_matrix':{'tn':int(tn),'fp':int(fp),'fn':int(fn),'tp':int(tp)},'classification_report':classification_report(test.mapped_label,pred,target_names=['benign','attack'],output_dict=True,zero_division=0),'warning':'External dataset labels may define prompt injection differently from SentinelLLM’s combined attack label. Review label semantics and licensing before interpreting results.'}
    args.output.parent.mkdir(exist_ok=True,parents=True); args.output.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
