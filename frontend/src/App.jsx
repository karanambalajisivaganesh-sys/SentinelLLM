import React, { useState } from 'react';
import Header from './components/Header';
import PromptInput from './components/PromptInput';
import PipelineStatus from './components/PipelineStatus';
import AnalysisResult from './components/AnalysisResult';
import './App.css';

// FastAPI Backend URL (Local development)
const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');

// Helper to generate a random session ID for multi-turn behavioral tracking
function generateSessionId() {
  return 'sess_' + Math.random().toString(36).substring(2, 10);
}

export default function App() {
  const [prompt, setPrompt] = useState('');
  const [sessionId, setSessionId] = useState(generateSessionId());
  const [result, setResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [apiError, setApiError] = useState(null);

  // 7-Stage security pipeline states
  const initialPipeline = {
    validation: 'pending',
    preprocessing: 'pending',
    ml: 'pending',
    rules: 'pending',
    behavior: 'pending',
    risk: 'pending',
    policy: 'pending',
  };

  const [statusState, setStatusState] = useState(initialPipeline);

  // Execute Analysis Workflow
  const handleAnalyze = async () => {
    setApiError(null);
    setResult(null);

    // Validate prompt locally first
    if (!prompt || !prompt.trim()) {
      setResult({
        success: false,
        error: "Prompt cannot be empty. Please enter a valid prompt string.",
        processing_summary: "Validation failed: Empty prompt received."
      });
      setStatusState({
        ...initialPipeline,
        validation: 'error'
      });
      return;
    }

    setIsLoading(true);

    // Set initial processing status
    setStatusState({
      validation: 'processing',
      preprocessing: 'pending',
      ml: 'pending',
      rules: 'pending',
      behavior: 'pending',
      risk: 'pending',
      policy: 'pending',
    });

    try {
      // Small artificial delay (250ms) so user can perceive the pipeline stage transition
      await new Promise((res) => setTimeout(res, 250));

      const response = await fetch(`${API_BASE_URL}/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          prompt: prompt,
          session_id: sessionId
        })
      });

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }

      const data = await response.json();

      // Update pipeline status timeline to completed
      setStatusState({
        validation: data.success ? 'completed' : 'error',
        preprocessing: data.success ? 'completed' : 'pending',
        ml: data.success ? 'completed' : 'pending',
        rules: data.success ? 'completed' : 'pending',
        behavior: data.success ? 'completed' : 'pending',
        risk: data.success ? 'completed' : 'pending',
        policy: data.success ? 'completed' : 'error',
      });

      // Synchronize session ID from behavioral analysis if returned
      if (data.behavioral_analysis?.session_id) {
        setSessionId(data.behavioral_analysis.session_id);
      }

      setResult(data);

    } catch (err) {
      console.error('Backend API Error:', err);
      setApiError(
        'Backend Unavailable: Could not connect to FastAPI backend at http://localhost:8000. ' +
        'Please ensure backend is running using: uvicorn main:app --reload --port 8000'
      );
      setStatusState({
        ...initialPipeline,
        validation: 'error'
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleClear = () => {
    setPrompt('');
    setResult(null);
    setApiError(null);
    setStatusState(initialPipeline);
  };

  const handleNewSession = () => {
    const freshId = generateSessionId();
    setSessionId(freshId);
    setResult(null);
    setApiError(null);
    setStatusState(initialPipeline);
  };

  return (
    <div className="app-container">
      <Header />

      <main className="main-content">
        <PromptInput
          prompt={prompt}
          setPrompt={setPrompt}
          onAnalyze={handleAnalyze}
          onClear={handleClear}
          isLoading={isLoading}
          sessionId={sessionId}
          onNewSession={handleNewSession}
        />

        <PipelineStatus statusState={statusState} />

        {apiError && (
          <div className="backend-offline-banner">
            <div className="banner-text">
              <h4>FastAPI Connection Warning</h4>
              <p>{apiError}</p>
            </div>
          </div>
        )}

        <AnalysisResult result={result} />
      </main>

      <footer className="app-footer">
        <p>SentinelLLM • Adaptive Behavioral Security Framework for LLMs</p>
        <p className="footer-sub">Computer Science Senior Project • React + FastAPI Architecture</p>
      </footer>
    </div>
  );
}
