import spacy
#load nlp model 
nlp = spacy.load("en_core_web_sm")

def parse_user_input(user_input: str):
    doc = nlp(user_input)
    category = "General"
    quantity = 1
    items = []

    diet_keywords = {"eat", "ate", "drink", "drank", "have", "had", "consume"}
    fitness_keywords = {"run", "ran", "lift", "lifted", "workout", "gym", "train"}

    #simple rule-based parsing
    for token in doc:
        if token.like_num:
            if token.text.isdigit():
                quantity = int(token.text)
        if token.lemma_ in diet_keywords:
            category = "Diet/Nutrition"
        elif token.lemma_ in fitness_keywords:
            category = "Fitness/Exercise"

    for chunk in doc.noun_chunks:
        if chunk.root.pos_ != "PRON":  #ignore pronouns
            items.append(chunk.text)
    
    #combine items into category if possible
    if items:
        category += f" - [{', '.join(items)}]"

    return {
        "parsed_category": category,
        "quantity": quantity
    }