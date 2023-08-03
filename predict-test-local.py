import csv
import numpy as np
import tensorflow as tf
import string

class str2vec:
    """Encode string to the vector of integers using an alphabet."""

    EN_US_ALPHABET = string.printable

    TL_DOMAINS = ["tunnel.tuns.org.", "hidemyself.org.", "tunnel.example.org."]

    def __init__(self, alphabet: str, maxlen: int = 256) -> None:
        self.corpus = {ch: pos + 1 for pos, ch in enumerate(alphabet)}
        self.alphabet = alphabet
        self.maxlen = maxlen

    @property
    def corpus_size(self):
        return len(self.corpus)

    def convert(self, s: bytes) -> np.array:
        for d in self.TL_DOMAINS:
            s = s.replace(d, "")

        maxlen = min(len(s), self.maxlen)
        str2idx = np.zeros(self.maxlen, dtype="int64")

        for i in range(1, maxlen + 1):
            c = s[-i]
            str2idx[i - 1] = self.corpus[c] if c in self.corpus else 0
        return str2idx

    def decode(self, i: int) -> str:
        return self.alphabet[i - 1] if 0 < i < len(self.alphabet) else " "


# Define encoder for English/US alphabet.
en2vec = str2vec(str2vec.EN_US_ALPHABET)

# Create an instance of the class that contains the predict_proba function
class MaliciousModel:
    def __init__(self, model):
        self.model = model

    def predict_proba(self, qname: str) -> float:
        """Returns a probability between 0 and 1 that given *qname* is malicious."""
        x = en2vec.convert(qname)
        return self.model.predict(np.asarray([x], dtype="int64"))[0][1]

# Load the model from the saved path
loaded_model = tf.keras.models.load_model('models/model-best-bubnov-rcnn.h5')

# Create an instance of the class using the loaded model
malicious_model = MaliciousModel(loaded_model)

# Define encoder for English/US alphabet.
en2vec = str2vec(str2vec.EN_US_ALPHABET)

def get_potential_dga_domains(threshold=0.9):
    # Open the domains.csv file
    with open('dga_domains_dataset/domains.csv', 'r', encoding='utf-8') as domains_file:
        # Create a CSV reader object
        reader = csv.reader(domains_file)
        # Read all the rows from the CSV file
        domains = list(reader)

    # Create a list to store potential DGA domains
    potential_dga_domains = []

    # Iterate over each domain
    for domain in domains:
        domain = domain[0]
        # Check if it's a potential DGA domain based on the model's prediction
        probability = malicious_model.predict_proba(domain)
        if probability >= threshold:
            potential_dga_domains.append(domain)

    return potential_dga_domains

def update_blocklist(potential_dga_domains):
    # Write the potential DGA domains to the new blocklist file
    with open('custom_blocklist.txt', 'a+', encoding='utf-8') as blocklist_file:
        # Move file pointer to the beginning of the file
        blocklist_file.seek(0)
        # Read all existing entries in the blocklist file
        existing_entries = blocklist_file.readlines()
        for domain in potential_dga_domains:
            # Check if the entry already exists in the blocklist file before writing it
            if f'{domain}\n' not in existing_entries:
                blocklist_file.write(f'{domain}\n')

if __name__ == '__main__':
    potential_dga_domains = get_potential_dga_domains(threshold=0.9)
    update_blocklist(potential_dga_domains)
