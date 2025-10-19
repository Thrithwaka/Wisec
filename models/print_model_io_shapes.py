import os
import json
import numpy as np

# For Keras/TensorFlow
from tensorflow.keras.models import load_model

# For traditional ML pickle models
import pickle

MODEL_DIR = r"C:\Users\thrit\Desktop\Wisec\models"

def print_keras_model_io_shapes(model_path):
    try:
        model = load_model(model_path)
        print(f"\nModel: {os.path.basename(model_path)}")
        try:
            print(f"Input shape(s): {model.input_shape}")
        except Exception as e:
            print(f"Error getting input shape: {e}")
        try:
            print(f"Output shape(s): {model.output_shape}")
        except Exception as e:
            print(f"Error getting output shape: {e}")
    except Exception as e:
        print(f"Failed to load Keras model '{model_path}': {e}")

def print_pickle_model_info(model_path):
    try:
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        print(f"\nPickle model: {os.path.basename(model_path)}")
        # Pickle models usually don't have input/output shapes directly.
        # We can print some info if available.
        print(f"Model type: {type(model)}")
        # Optionally, test a dummy input shape if possible
    except Exception as e:
        print(f"Failed to load pickle model '{model_path}': {e}")

def main():
    for filename in os.listdir(MODEL_DIR):
        full_path = os.path.join(MODEL_DIR, filename)
        if filename.endswith('.h5'):
            print_keras_model_io_shapes(full_path)
        elif filename.endswith('.pkl'):
            print_pickle_model_info(full_path)
        elif filename.endswith('.json'):
            # Optionally print JSON metadata contents
            print(f"\nMetadata JSON: {filename}")
            try:
                with open(full_path, 'r') as f:
                    metadata = json.load(f)
                print(json.dumps(metadata, indent=2))
            except Exception as e:
                print(f"Failed to read JSON metadata '{filename}': {e}")
        else:
            print(f"\nSkipping unknown file type: {filename}")

if __name__ == "__main__":
    main()
