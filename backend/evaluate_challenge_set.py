"""Evaluate the active trained classifier on the fixed challenge set.
This set is not used for fitting or threshold selection and is not a real-world benchmark.
"""
from pathlib import Path
import json
import pandas as pd
import joblib
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import sys
sys.path.insert(0, str(BASE)) if 'BASE' in globals() else None

BASE=Path(__file__).resolve().parent
import sys
sys.path.insert(0, str(BASE))
from detection.risk_engine import evaluate_risk_policy
DATA=BASE/'training_data'/'independent_challenge_set.csv'
MODEL=BASE/'ml_models'/'sentinelllm_tfidf_logreg.joblib'
METRICS=BASE/'ml_models'/'training_metrics.json'
OUT=BASE/'ml_models'/'challenge_set_results.json'
PRED=BASE/'ml_models'/'challenge_set_predictions.csv'

def main():
    df=pd.read_csv(DATA).dropna(subset=['text','label']).copy()
    metrics=json.loads(METRICS.read_text(encoding='utf-8'))
    threshold=float(metrics['threshold'])
    model=joblib.load(MODEL)
    probs=model.predict_proba(df.text.astype(str).tolist())[:,1]
    pred=(probs>=threshold).astype(int)
    tn,fp,fn,tp=confusion_matrix(df.label.astype(int),pred,labels=[0,1]).ravel()
    df['attack_score']=probs; df['predicted_label']=pred; df['correct']=df.label.astype(int)==pred
    decisions=[]
    for text, score in zip(df.text.astype(str), probs):
        ml_result={'success':True,'attack_score':float(score),'is_attack':bool(score>=threshold),'predicted_class':'attack' if score>=threshold else 'benign','threshold_used':threshold}
        decision=evaluate_risk_policy(text, {'encoding_detected':[],'obfuscation_detected':False,'zero_width_detected':False}, ml_result, {'session_risk_score':0.0,'repeated_attack_detected':False,'escalation_detected':False,'recent_suspicious_count':0})
        decisions.append(decision['policy_decision'])
    df['policy_decision']=decisions
    policy_positive=df.policy_decision.isin(['BLOCK','FLAG_FOR_REVIEW']).astype(int)
    policy_tn,policy_fp,policy_fn,policy_tp=confusion_matrix(df.label.astype(int),policy_positive,labels=[0,1]).ravel()
    df.to_csv(PRED,index=False)
    per_topic={}
    for topic,g in df.assign(pred=pred).groupby('topic'):
        per_topic[topic]={'rows':int(len(g)),'accuracy':float(accuracy_score(g.label,g.pred)), 'false_positives':int(((g.label==0)&(g.pred==1)).sum()), 'false_negatives':int(((g.label==1)&(g.pred==0)).sum())}
    result={
        'dataset':'training_data/independent_challenge_set.csv', 'rows':int(len(df)),
        'provenance':'Hand-authored internal challenge set; not used for model fitting or threshold selection, but reviewed and used to tune policy rules; not an independent final-policy benchmark.',
        'threshold':threshold, 'accuracy':float(accuracy_score(df.label,pred)),
        'precision_attack':float(precision_score(df.label,pred,zero_division=0)),
        'recall_attack':float(recall_score(df.label,pred,zero_division=0)),
        'f1_attack':float(f1_score(df.label,pred,zero_division=0)),
        'confusion_matrix':{'tn':int(tn),'fp':int(fp),'fn':int(fn),'tp':int(tp)},
        'policy_layer':{'attack_detected_if_block_or_review':True,'accuracy':float(accuracy_score(df.label,policy_positive)),'benign_flag_or_block_rate':float(policy_fp/max(1,policy_tn+policy_fp)),'attack_detection_rate':float(policy_tp/max(1,policy_tp+policy_fn)),'confusion_matrix':{'tn':int(policy_tn),'fp':int(policy_fp),'fn':int(policy_fn),'tp':int(policy_tp)},'decision_counts':df.policy_decision.value_counts().to_dict()},
        'per_topic':per_topic,
        'false_positives':df[(df.label==0)&(~df.correct)][['text','topic','attack_score','policy_decision']].to_dict(orient='records'),
        'false_negatives':df[(df.label==1)&(~df.correct)][['text','topic','attack_score','policy_decision']].to_dict(orient='records'),
        'limitations':['Small internal challenge set; labels and phrasing authored for this project.', 'The policy rules were reviewed and tuned against observed cases in this set, so combined-policy metrics are development/regression metrics, not an independent final evaluation.', 'Does not establish real-world generalization; obtain a separately collected, licensed, human-reviewed benchmark.', 'This set tests binary attack classification but cannot validate all indirect, multilingual, encoded, long-context, or multi-turn attacks.']
    }
    OUT.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('false_positives','false_negatives','limitations')},indent=2))
    print('False positives:')
    for x in result['false_positives']: print(f"  score={x['attack_score']:.3f} topic={x['topic']} text={x['text']}")
    print('False negatives:')
    for x in result['false_negatives']: print(f"  score={x['attack_score']:.3f} topic={x['topic']} text={x['text']}")

if __name__=='__main__': main()
