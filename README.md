# AndroidXmlParserWithOwaspFlaw
Sample Android project demonstrating that the OWASP recommended Features cannot be set on the
underlying parser that Android uses.

See https://issuetracker.google.com/issues/149815313

Method exhibiting the problematic behavior is: com.example.xmlparserapplication.ImporterEditable.secureDocumentFactory
