Ocean Vocabulary Mapper

A web-based tool for harmonizing ocean-related data vocabularies to enhance reusability and interoperability. It maps terms to SeaDataNet and CF Convention standards using string similarity, with secure user authentication and 2FA.

Features





Maps ocean data terms to standardized vocabularies (SeaDataNet, CF).



Secure login with bcrypt password hashing and TOTP-based 2FA.



Stores user mappings in SQLite for reuse.



Exports mappings in JSON-LD for interoperability.



Simple React-based UI with Tailwind CSS.

Setup





Install Dependencies:

pip install flask flask-wtf bcrypt pyotp pyjwt python-Levenshtein



Organize Files:





Place app.py in the root directory.



Create a templates folder with index.html, login.html, register.html, and mapper.html.



Run the Application:

python app.py



Access:





Open http://localhost:5000.



Register, save the TOTP secret, and set up 2FA (e.g., Google Authenticator).



Log in to use the mapper.

Usage





Input Terms: Enter terms (e.g., "temperature") in the text area, one per line.



Select Standard: Choose "SeaDataNet" or "CF".



Map Terms: Submit to view mapped terms, URIs, and similarity scores.



Export: Download mappings as JSON-LD.

Notes





Update secret keys in app.py for production.



Extend with larger vocabularies or semantic matching (e.g., BERT).



Deploy on a cloud platform for scalability.

License

MIT License
