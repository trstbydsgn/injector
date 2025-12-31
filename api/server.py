"""
Flask API Server for Prompt Injection Classifier
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from classifier import PromptInjectionClassifier
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for web demo

# Initialize classifier
classifier = PromptInjectionClassifier()


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'prompt-injection-classifier'
    })


@app.route('/v1/classify', methods=['POST'])
def classify():
    """
    Classify input for prompt injection
    
    Request body:
    {
        "input": "text to analyze",
        "threshold": 0.7 (optional),
        "include_features": true (optional)
    }
    
    Response:
    {
        "score": 0.85,
        "risk": "high",
        "ml_score": 0.72,
        "rule_score": 0.90,
        "detected_patterns": [...],
        "recommendation": "...",
        "features": {...} (if requested)
    }
    """
    try:
        # Validate request
        if not request.is_json:
            return jsonify({
                'error': 'Content-Type must be application/json'
            }), 400
        
        data = request.get_json()
        
        # Extract parameters
        input_text = data.get('input', '')
        threshold = data.get('threshold', 0.7)
        include_features = data.get('include_features', False)
        
        # Validate input
        if not input_text:
            return jsonify({
                'error': 'Input text is required'
            }), 400
        
        if not isinstance(threshold, (int, float)) or not 0 <= threshold <= 1:
            return jsonify({
                'error': 'Threshold must be a number between 0 and 1'
            }), 400
        
        # Classify
        result = classifier.classify(input_text, threshold)
        
        # Remove features if not requested
        if not include_features:
            result.pop('features', None)
        
        logger.info(f"Classified input - Risk: {result['risk']}, Score: {result['score']}")
        
        return jsonify(result), 200
    
    except Exception as e:
        logger.error(f"Error classifying input: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500


@app.route('/v1/batch', methods=['POST'])
def batch_classify():
    """
    Classify multiple inputs in batch
    
    Request body:
    {
        "inputs": ["text1", "text2", ...],
        "threshold": 0.7 (optional)
    }
    
    Response:
    {
        "results": [
            {"input": "text1", "score": 0.5, ...},
            {"input": "text2", "score": 0.8, ...}
        ],
        "summary": {
            "total": 2,
            "high_risk": 1,
            "medium_risk": 0,
            "low_risk": 1
        }
    }
    """
    try:
        if not request.is_json:
            return jsonify({
                'error': 'Content-Type must be application/json'
            }), 400
        
        data = request.get_json()
        inputs = data.get('inputs', [])
        threshold = data.get('threshold', 0.7)
        
        if not isinstance(inputs, list):
            return jsonify({
                'error': 'inputs must be a list'
            }), 400
        
        if len(inputs) > 100:
            return jsonify({
                'error': 'Maximum 100 inputs per batch'
            }), 400
        
        # Classify all inputs
        results = []
        summary = {'total': len(inputs), 'high_risk': 0, 'medium_risk': 0, 'low_risk': 0}
        
        for input_text in inputs:
            result = classifier.classify(input_text, threshold)
            result['input'] = input_text[:100]  # Truncate for response
            result.pop('features', None)  # Remove features for batch
            results.append(result)
            
            # Update summary
            summary[f"{result['risk']}_risk"] += 1
        
        logger.info(f"Batch classified {len(inputs)} inputs")
        
        return jsonify({
            'results': results,
            'summary': summary
        }), 200
    
    except Exception as e:
        logger.error(f"Error in batch classification: {str(e)}")
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500


@app.route('/v1/patterns', methods=['GET'])
def get_patterns():
    """Get list of detection patterns"""
    patterns = [
        {
            'name': p['name'],
            'weight': p['weight']
        }
        for p in classifier.patterns
    ]
    return jsonify({'patterns': patterns})


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║   Prompt Injection Classifier API Server             ║
    ║   Running on http://localhost:5000                    ║
    ╚═══════════════════════════════════════════════════════╝
    
    Available endpoints:
    • GET  /health           - Health check
    • POST /v1/classify      - Classify single input
    • POST /v1/batch         - Classify multiple inputs
    • GET  /v1/patterns      - List detection patterns
    """)
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )
