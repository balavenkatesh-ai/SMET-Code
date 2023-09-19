from SMET import map_text,map_attack_vector
import pandas as pd
from collections import defaultdict

#map attack vectors to ATT&CK

# AV1 = 'take screenshot'
# mapping1 = map_attack_vector(AV1)

# AV2 = 'delete logs'
# mapping2 = map_attack_vector(AV2)

# AV3 = 'exfiltrate data to C2 server'
# mapping3 = map_attack_vector(AV3)

#===================CVE Text ===============

cve ="""An Out of Bounds flaw was found fig2dev version 3.2.8a. A flawed bounds check in read_objects() could allow an attacker to provide a crafted malicious input causing the application to either crash or in some cases cause memory corruption. 
The highest threat from this vulnerability is to integrity as well as system availability."""

# cve = """Dell Encryption versions prior to 10.7 and Dell Endpoint Security Suite versions prior to 2.7 contain a privilege escalation vulnerability due to incorrect permissions. 
# A local malicious user with low privileges could potentially exploit this vulnerability to gain elevated privilege on the affected system with the help of a symbolic link."""

# cve = """It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. 
# This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context 
# Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an 
# information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this 
# issue by removing support for message lookup patterns and disabling JNDI functionality by default."""


#===================Test single CVE ===============


# mapping = map_text(cve,CVE = True) #map CVE to ATT&CK
# print(mapping)


#===================Test Entire CSV File ===============

csv_file = 'arif_cve_data.csv'  
df = pd.read_csv(csv_file)

mapping_results = []
first_mapping_results = []

for index, row in df.iterrows():
    cve_description = row['Description']
    technique = map_text(cve_description)
    mapping_results.append(technique)
    if technique:
        first_mapping_results.append(technique[0])
    else:
        first_mapping_results.append("")


df['High Probability of Model Results'] = first_mapping_results
df['Model Results'] = mapping_results

df.to_csv(csv_file, index=False)





# sorted_list = sorted(mapping, key=lambda x: x[1], reverse=True)
# print(sorted_list)

#map any text to ATT&CK
# cve = ""
# mapping = map_text(cve,CVE = False)


#get embedding using ATT&CK 
# from sentence_transformers import SentenceTransformer

# text = ""
# emb_model = SentenceTransformer("basel/ATTACK-BERT")
# embedding = emb_model.encode(text)



