try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import LSTM, Embedding, Dense
    HAS_TF = True
except ImportError:
    HAS_TF = False


def build_seq_model(vocab_size=5000, embedding_dim=64, lstm_units=64, num_classes=2):
    if not HAS_TF:
        raise ImportError("TensorFlow not installed")
    model = Sequential()
    model.add(Embedding(vocab_size, embedding_dim, input_length=50))
    model.add(LSTM(lstm_units))
    model.add(Dense(num_classes, activation="softmax"))
    model.compile(loss="categorical_crossentropy", optimizer="adam", metrics=["accuracy"])
    return model
