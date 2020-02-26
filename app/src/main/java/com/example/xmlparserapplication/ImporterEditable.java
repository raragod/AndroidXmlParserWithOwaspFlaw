package com.example.xmlparserapplication;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.text.Editable;
import android.text.Spannable;
import android.text.SpannableString;
import android.text.SpannableStringBuilder;
import android.text.style.BackgroundColorSpan;
import android.text.style.CharacterStyle;
import android.text.style.ForegroundColorSpan;
import android.text.style.RelativeSizeSpan;
import android.text.style.StyleSpan;
import android.text.style.TypefaceSpan;
import android.text.style.UnderlineSpan;
import android.util.Log;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

class ImporterEditable {
    private static final String LOG_TAG = ImporterEditable.class.getSimpleName();

    private final Context context;
    private String docxFilePath;
    private Editable result;
    private static final float defaultSize = 12.0F;

    ImporterEditable(Context context, String docxFilePath) {
        this.context = context;
        this.docxFilePath = docxFilePath;
        result = null;
    }

    Editable importEditable() {
        result = new SpannableStringBuilder("");
        processDocumentXmlFile(new File(docxFilePath));
        return result;
    }

    private void processDocumentXmlFile(File wordDocumentXmlFile) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            secureDocumentFactory(factory);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(wordDocumentXmlFile);
            NodeList nodes = document.getElementsByTagName("w:body");
            if (nodes.getLength() > 0) {
                NodeList documentNodes = nodes.item(0).getChildNodes();
                for (int i = 0; i < documentNodes.getLength(); ++i) {
                    if (documentNodes.item(i) instanceof Element) {
                        Element element = (Element) documentNodes.item(i);
                        if (element.getTagName().equalsIgnoreCase("w:p")) {
                            // process paragraph
                            processParagraph(element);
                        }
                    }
                }
            }
        } catch (ParserConfigurationException | IOException | SAXException e) {
            Log.e(LOG_TAG, "Error in processDocumentXmlFile", e);
        }
    }

    private void secureDocumentFactory(DocumentBuilderFactory dbf) throws IOException {
        // Adding recommendations for securing the DocumentBuilderFactory as per OWASP recommendations
        // given here: https://owasp.org/www-project-cheat-sheets/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#JAXP_DocumentBuilderFactory.2C_SAXParserFactory_and_DOM4J
        // This method is copied from the above page.
        String FEATURE = null;
        // This is the PRIMARY defense. If DTDs (doctypes) are disallowed, almost all
        // XML entity attacks are prevented
        // Xerces 2 only - http://xerces.apache.org/xerces2-j/features.html#disallow-doctype-decl
        FEATURE = "http://apache.org/xml/features/disallow-doctype-decl";
        try {
            dbf.setFeature(FEATURE, true);
        } catch (ParserConfigurationException e) {
            // This should catch a failed setFeature feature
            Log.i(LOG_TAG, "ParserConfigurationException was thrown. The feature '" + FEATURE
                    + "' is probably not supported by your XML processor.", e);
        }

        // If you can't completely disable DTDs, then at least do the following:
        // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-general-entities
        // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-general-entities
        // JDK7+ - http://xml.org/sax/features/external-general-entities
        FEATURE = "http://xml.org/sax/features/external-general-entities";
        try {
            dbf.setFeature(FEATURE, false);
        } catch (ParserConfigurationException e) {
            // This should catch a failed setFeature feature
            Log.i(LOG_TAG, "ParserConfigurationException was thrown. The feature '" + FEATURE
                    + "' is probably not supported by your XML processor.", e);
        }

        // Xerces 1 - http://xerces.apache.org/xerces-j/features.html#external-parameter-entities
        // Xerces 2 - http://xerces.apache.org/xerces2-j/features.html#external-parameter-entities
        // JDK7+ - http://xml.org/sax/features/external-parameter-entities
        FEATURE = "http://xml.org/sax/features/external-parameter-entities";
        try {
            dbf.setFeature(FEATURE, false);
        } catch (ParserConfigurationException e) {
            // This should catch a failed setFeature feature
            Log.i(LOG_TAG, "ParserConfigurationException was thrown. The feature '" + FEATURE
                    + "' is probably not supported by your XML processor.", e);
        }

        // Disable external DTDs as well
        FEATURE = "http://apache.org/xml/features/nonvalidating/load-external-dtd";
        try {
            dbf.setFeature(FEATURE, false);
        } catch (ParserConfigurationException e) {
            // This should catch a failed setFeature feature
            Log.i(LOG_TAG, "ParserConfigurationException was thrown. The feature '" + FEATURE
                    + "' is probably not supported by your XML processor.", e);
        }

        // and these as well, per Timothy Morgan's 2014 paper: "XML Schema, DTD, and Entity Attacks"
        try {
            dbf.setXIncludeAware(false);
        } catch (Exception e) {
            // This should catch a failed setFeature feature
            Log.i(LOG_TAG, "Exception calling setXIncludeAware", e);
        }

        // this is the only call that seems to work as no exception is thrown here.
        dbf.setExpandEntityReferences(false);

        // And, per Timothy Morgan: "If for some reason support for inline DOCTYPEs are a requirement, then
        // ensure the entity settings are disabled (as shown above) and beware that SSRF attacks
        // (http://cwe.mitre.org/data/definitions/918.html) and denial
        // of service attacks (such as billion laughs or decompression bombs via "jar:") are a risk."

        // remaining parser logic
    }

    private void processParagraph(Element paragraphElement) {
        NodeList paragraphNodes = paragraphElement.getChildNodes();
        for (int i = 0; i < paragraphNodes.getLength(); ++i) {
            if (paragraphNodes.item(i) instanceof Element) {
                Element element = (Element) paragraphNodes.item(i);
                if (element.getTagName().equalsIgnoreCase("w:r")) {
                    processTextRun(element);
                }
            }
        }
        // add new line after the paragraph
        result.append("\n");
    }

    private void processTextRun(Element textRunElement) {
        NodeList textRunNodes = textRunElement.getChildNodes();
        ArrayList<CharacterStyle> textRunStyle = null;
        for (int i = 0; i < textRunNodes.getLength(); ++i) {
            if (textRunNodes.item(i) instanceof Element) {
                Element element = (Element) textRunNodes.item(i);
                if (element.getTagName().equalsIgnoreCase("w:rPr")) {
                    textRunStyle = getTextRunProperties(element);
                } else if (element.getTagName().equalsIgnoreCase("w:t")) {
                    processTextElement(element, textRunStyle);
                } else if (element.getTagName().equalsIgnoreCase("w:drawing")) {
//                    processDrawing(element);
                } else {
                    // ignore other type of tags
//                    containsUnsupportedContent = true;
                }
            }
        }
    }


    private void processTextElement(Element textElement, ArrayList<CharacterStyle> textRunStyle) {
        SpannableString text = new SpannableString(textElement.getTextContent());
        if (textRunStyle != null && textRunStyle.size() > 0) {
            // apply styles
            for (int i = 0; i < textRunStyle.size(); ++i) {
                CharacterStyle style = textRunStyle.get(i);
                text.setSpan(style, 0, text.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            }
        }
        result.append(text);
    }

    private ArrayList<CharacterStyle> getTextRunProperties(Element textRunPropertiesElement) {
        ArrayList<CharacterStyle> textRunStyle = null;
        NodeList textRunPropertiesNodes = textRunPropertiesElement.getChildNodes();
        if (textRunPropertiesNodes.getLength() > 0) {
            textRunStyle = new ArrayList<CharacterStyle>();
        }
        for (int i = 0; i < textRunPropertiesNodes.getLength(); ++i) {
            if (textRunPropertiesNodes.item(i) instanceof Element) {
                Element element = (Element) textRunPropertiesNodes.item(i);
                if (element.getTagName().equalsIgnoreCase("w:b")) {
                    textRunStyle.add(new StyleSpan(Typeface.BOLD));
                } else if (element.getTagName().equalsIgnoreCase("w:i")) {
                    textRunStyle.add(new StyleSpan(Typeface.ITALIC));
                } else if (element.getTagName().equalsIgnoreCase("w:u") && !element.getAttribute("w:val").equalsIgnoreCase("none")) {
                    textRunStyle.add(new UnderlineSpan());
                } else if (element.getTagName().equalsIgnoreCase("w:sz")) {
                    int size = Integer.parseInt(element.getAttribute("w:val"));
                    textRunStyle.add(new RelativeSizeSpan(size / defaultSize / 2));
                } else if (element.getTagName().equalsIgnoreCase("w:color")) {
                    int color = Color.parseColor("#" + element.getAttribute("w:val"));
                    textRunStyle.add(new ForegroundColorSpan(color));
                } else if (element.getTagName().equalsIgnoreCase("w:highlight")) {
                    String colorValue = element.getAttribute("w:val");
                    int color = getStringColorRepresentation(colorValue);
                    textRunStyle.add(new BackgroundColorSpan(color));
                } else if (element.getTagName().equalsIgnoreCase("w:rFonts")) {
                    String typefaceName = element.getAttribute("w:ascii");
                    textRunStyle.add(new TypefaceSpan(typefaceName));
                }
            }
        }
        return textRunStyle;
    }

    private int getStringColorRepresentation(String colorValue) {
        int color = Color.BLACK;
        if (colorValue.equals("red")) {
            color = Color.RED;
        } else if (colorValue.equals("yellow")) {
            color = Color.YELLOW;
        } else if (colorValue.equals("green")) {
            color = Color.GREEN;
        } else if (colorValue.equals("blue")) {
            color = Color.BLUE;
        } else if (colorValue.equals("white")) {
            color = Color.WHITE;
        } else if (colorValue.equals("none")) {
            color = Color.TRANSPARENT;
        }
        return color;
    }

    public Editable getEditable() {
        return result;
    }


}
