"""
SentinelLLM - FastAPI Backend Application

Provides endpoints for prompt validation, preprocessing, encoding detection,
Unicode analysis, machine learning prompt-injection classification, multi-turn
behavioral session tracking, and explainable policy decisions (ALLOW, FLAG_FOR_REVIEW, BLOCK).
Updated for SentinelLLM Phase 5.
"""

from contextlib import asynccontextmanager
import os
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from models import AnalyzeRequest, AnalyzeResponse, MLResult, BehavioralResult, RiskAssessment
from preprocessing.preprocessor import preprocess_prompt
from detection.classifier import PromptClassifier, classify_prompt
from detection.risk_engine import evaluate_risk_policy
from behavior.analyzer import analyze_session_behavior


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler to pre-load the ML model at startup.
    """
    classifier = PromptClassifier.get_instance()
    if classifier.is_loaded:
        print(f"[SentinelLLM] Loaded active model: {classifier.model_name} from {classifier.model_path}")
    else:
        print(f"[SentinelLLM WARNING] Could not load model: {classifier.load_error}")
    yield


app = FastAPI(
    title="SentinelLLM Security API",
    description="Adaptive Behavioral Security Framework for LLMs - Preprocessing, ML Detection, Behavior & Policy Engine",
    version="4.2.0",
    lifespan=lifespan
)

# Restrict credentialed CORS to local development origins by default. Deployments
# can override this with a comma-separated CORS_ORIGINS environment variable.
_default_origins = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173"
_allowed_origins = [origin.strip() for origin in os.environ.get("CORS_ORIGINS", _default_origins).split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


@app.get(
    "/health",
    tags=["Health"],
    summary="API Health Check",
    response_model=dict
)
def health_check():
    """
    Health check endpoint to verify backend server status and model availability.
    """
    classifier = PromptClassifier.get_instance()
    return {
        "status": "ok",
        "service": "SentinelLLM preprocessing, detection, behavioral, and policy API",
        "model_loaded": classifier.is_loaded,
        "active_model": classifier.model_name,
        "model_error": classifier.load_error,
    }


@app.post(
    "/analyze",
    tags=["Analysis"],
    summary="Analyze, classify, and apply security policy to incoming prompts",
    response_model=AnalyzeResponse
)
def analyze_prompt_endpoint(request: AnalyzeRequest):
    """
    Primary analysis endpoint. Accepts a user prompt (and optional session_id), validates it,
    performs normalization, detects encodings (Base64, Hex, URL), identifies Unicode anomalies,
    classifies semantic attack patterns using ML, tracks multi-turn behavioral session context,
    and returns an explainable policy decision (ALLOW, FLAG_FOR_REVIEW, BLOCK).
    """
    # Step 1: Preprocessing pipeline
    result = preprocess_prompt(request.prompt)

    # Handle input validation failures gracefully
    if not result.get("success", True):
        return AnalyzeResponse(
            success=False,
            original_text=request.prompt or "",
            normalized_text="",
            input_type="unknown",
            encoding_detected=[],
            obfuscation_detected=False,
            obfuscation_methods=[],
            unicode_anomaly_detected=False,
            unicode_anomalies=[],
            zero_width_detected=False,
            decoded_content=None,
            cleaned_content=None,
            processing_summary=result.get("processing_summary", "Validation error occurred."),
            ml_result=None,
            behavioral_analysis=None,
            risk_assessment=None,
            policy_decision=None,
            error=result.get("error", "Invalid prompt input.")
        )

    # Step 2: Select appropriate representation for ML inference
    if result.get("decoded_content"):
        text_for_ml = result["decoded_content"]
    elif result.get("cleaned_content"):
        text_for_ml = result["cleaned_content"]
    else:
        text_for_ml = result.get("normalized_text", request.prompt)

    # Step 3: ML Inference
    raw_ml = classify_prompt(text_for_ml)
    ml_obj = MLResult(
        success=raw_ml["success"],
        model_name=raw_ml["model_name"],
        model_version=raw_ml["model_version"],
        predicted_label=raw_ml["predicted_label"],
        predicted_class=raw_ml["predicted_class"],
        attack_score=raw_ml["attack_score"],
        threshold_used=raw_ml["threshold_used"],
        is_attack=raw_ml["is_attack"],
        text_evaluated=raw_ml["text_evaluated"],
        error=raw_ml["error"]
    )

    # Step 4: Multi-turn Behavioral Analysis
    raw_behavior = analyze_session_behavior(
        session_id=request.session_id,
        text_for_analysis=text_for_ml,
        ml_result=raw_ml,
        preprocessing_result=result,
    )
    behavior_obj = BehavioralResult(**raw_behavior)

    # Step 5: Risk Engine & Decision Policy Synthesis
    raw_risk = evaluate_risk_policy(
        text=text_for_ml,
        preprocessing_result=result,
        ml_result=raw_ml,
        behavioral_result=raw_behavior
    )
    risk_obj = RiskAssessment(**raw_risk)

    # Step 6: Update processing summary with final Policy Decision
    summary = result.get("processing_summary", "")
    if ml_obj.success:
        score_str = f"{ml_obj.attack_score:.4f}" if ml_obj.attack_score is not None else "N/A"
        ml_summary = f"ML ({ml_obj.model_name}) classified input as '{ml_obj.predicted_class}' (attack score: {score_str}, threshold: {ml_obj.threshold_used})."
        if summary and not summary.endswith("."):
            summary += "."
        summary = f"{summary} {ml_summary}".strip()
    elif ml_obj.error:
        summary = f"{summary} [ML Classification unavailable: {ml_obj.error}]".strip()

    # Append policy decision summary
    decision_summary = f"Policy Decision: {risk_obj.policy_decision} (Risk score: {risk_obj.risk_score:.1f}/100, level: {risk_obj.risk_level})."
    summary = f"{summary} {decision_summary}".strip()

    result["processing_summary"] = summary

    return AnalyzeResponse(
        **result,
        ml_result=ml_obj,
        behavioral_analysis=behavior_obj,
        risk_assessment=risk_obj,
        policy_decision=risk_obj.policy_decision
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
