import shutil
import base64

shutil.copyfile('kalender-2021.pdf', 'progress.pdf')

pdf_file = open('progress.pdf', 'ab')
signature_file = open('signature.txt', 'rb')

pdf_file.write(base64.b64encode(signature_file.read()))

pdf_file.close()
signature_file.close()

# Split

combined_file = open('progress.pdf', 'rb')

combined_bytes = combined_file.read()

combined_file.close()

splited_chunks = combined_bytes.split(b'EOF')

signature_chunk = splited_chunks[-1]

splited_chunks.pop()
pdf_chunk = b''

for i in range(len(splited_chunks)):
    pdf_chunk += splited_chunks[i]
    pdf_chunk += b'EOF'

print(signature_chunk)
print(pdf_chunk)

new_pdf_file = open('new_pdf.pdf', 'wb')
new_signature_file = open('new_signature.txt', 'wb')

new_pdf_file.write(pdf_chunk)
new_signature_file.write(base64.b64decode(signature_chunk))