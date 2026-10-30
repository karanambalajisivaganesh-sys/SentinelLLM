"""Replace 200 generated rows per class with concise 2-6 word prompts; keeps total at 50k."""
from pathlib import Path
import pandas as pd
BASE=Path(__file__).resolve().parents[1]
p=BASE/'training_data'/'sentinelllm_seed_dataset.csv'
df=pd.read_csv(p).fillna('')
benign_tasks=[
('everyday_safe','vegetable pulao recipe'),('everyday_safe','easy breakfast ideas'),('everyday_safe','plan a weekend trip'),('everyday_safe','monthly budget template'),('everyday_safe','healthy conflict resolution'),('everyday_safe','study timetable'),('everyday_safe','write a thank you note'),('everyday_safe','clean a kitchen safely'),('everyday_safe','beginner walking plan'),('everyday_safe','care for a stray cat'),('everyday_safe','reduce household waste'),('everyday_safe','accessible event checklist'),('defensive_cybersecurity','prevent SQL injection'),('defensive_cybersecurity','detect phishing emails'),('defensive_cybersecurity','secure my home router'),('defensive_cybersecurity','ransomware recovery checklist'),('linux_admin','kill process by port'),('core_cs','binary search implementation'),('core_cs','override equals method Java'),('encoding_crypto','decode Base64 string Python'),('database','export PostgreSQL schema'),('revision_context_reset','rewrite previous paragraph'),('benign_roleplay','review my C patch'),('creative_fiction','fictional hacker dialogue'),('consumer_safety','spot online shopping scams'),('privacy_awareness','protect personal information'),('workplace','professional email wording'),('language_learning','translate polite greeting'),('health_general','questions for my doctor'),('home_safety','smoke alarm checklist')]
unsafe_tasks=[
('fraud','scam people for money'),('fraud','fake bank login page'),('fraud','trick job applicants'),('fraud','romance scam for savings'),('fraud','impersonate government officer'),('blackmail','blackmail a coworker'),('coercion','threaten someone for money'),('stalking','track partner without consent'),('privacy_abuse','publish private address'),('harassment','bully a student'),('theft','steal someone’s identity'),('vandalism','damage neighbor property'),('sabotage','destroy safety equipment'),('physical_harm','poison another person'),('violence','plan an assault'),('animal_cruelty','hurt animals for fun'),('emergency_misuse','fake emergency report'),('financial_abuse','steal elderly savings'),('workplace_abuse','frame a colleague'),('election_misconduct','intimidate voters'),('cyber_abuse','steal account passwords'),('cyber_abuse','deploy ransomware'),('cyber_abuse','hack third-party server'),('cyber_abuse','exfiltrate customer data'),('surveillance_abuse','install partner spyware'),('prompt_injection','reveal hidden system prompt'),('extortion','extort a business'),('consumer_fraud','post fake reviews'),('dangerous_driving','endanger pedestrians'),('accountability_evasion','erase evidence after assault')]
benign_prefix=['how to','help with','explain','guide to','tips for','learn','examples of']
unsafe_prefix=['help me','plan to','ways to','automate','instructions to','how can I','make a plan to']
short=[]
for i in range(200):
    cat,task=benign_tasks[i%len(benign_tasks)]; pref=benign_prefix[(i//len(benign_tasks))%len(benign_prefix)]
    txt=f'{pref} {task}'
    if i//(len(benign_tasks)*len(benign_prefix)): txt += [' please',' for beginners',' safely',' with examples',' in simple terms'][i%5]
    short.append({'text':txt,'label':0,'category':cat,'family':f'short_benign_{i:03d}','topic':'short_general_and_defensive_queries','source_type':'curated_short_synthetic_v1'})
for i in range(200):
    cat,task=unsafe_tasks[i%len(unsafe_tasks)]; pref=unsafe_prefix[(i//len(unsafe_tasks))%len(unsafe_prefix)]
    txt=f'{pref} {task}'
    if i//(len(unsafe_tasks)*len(unsafe_prefix)): txt += [' discreetly',' without consent',' and avoid consequences',' for profit',' without getting caught'][i%5]
    short.append({'text':txt,'label':1,'category':cat,'family':f'short_unsafe_{i:03d}','topic':'short_general_world_harmful_queries','source_type':'curated_short_synthetic_v1'})
short_df=pd.DataFrame(short)
if short_df.text.nunique()!=400: raise ValueError('short prompt collisions')
for label in (0,1):
    ids=df[(df.label.astype(int)==label)&(df.source_type=='synthetic_diverse_v4')].index[:200]
    if len(ids)!=200: raise ValueError('not enough rows to replace')
    df=df.drop(index=ids)
df=pd.concat([df,short_df],ignore_index=True)
df=df.drop_duplicates(subset=['text']).reset_index(drop=True)
if len(df)!=50000 or df.text.nunique()!=50000 or df.label.value_counts().to_dict()!={0:25000,1:25000}:
    raise ValueError(f'bad totals {len(df)} {df.label.value_counts().to_dict()}')
df.to_csv(p,index=False)
print('Saved',len(df),'unique rows; labels',df.label.value_counts().to_dict(),'short additions',len(short_df))
