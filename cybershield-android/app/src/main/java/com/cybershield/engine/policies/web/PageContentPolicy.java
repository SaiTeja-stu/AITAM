package com.cybershield.engine.policies.web;

import com.cybershield.domain.ContentType;
import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** WEB-04/05/06: hidden iframes, obfuscated inline JS, fake security-popup text. */
public class PageContentPolicy extends AbstractPolicy {

    public PageContentPolicy() {
        super("WEB-04", Set.of(ContentType.WEBPAGE, ContentType.URL));
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        if (ctx.html().trim().isEmpty()) return List.of();
        List<Signal> out = new ArrayList<>();
        Document doc = Jsoup.parse(ctx.html());

        boolean hiddenIframe = doc.select("iframe").stream().anyMatch(e -> {
            String style = e.attr("style").replaceAll("\\s", "").toLowerCase();
            return style.contains("display:none") || style.contains("visibility:hidden")
                    || "0".equals(e.attr("width")) || "0".equals(e.attr("height"));
        });
        if (hiddenIframe) {
            out.add(signal("Hidden iframe",
                    "The page loads an invisible embedded frame, a technique used for click-jacking and drive-by attacks.",
                    Severity.MEDIUM, 15));
        }

        String scripts = doc.select("script").html().toLowerCase();
        if (scripts.contains("eval(") && (scripts.contains("unescape(") || scripts.contains("fromcharcode")
                || scripts.contains("atob("))) {
            out.add(signal("Obfuscated JavaScript",
                    "Inline scripts on the page are heavily obfuscated, which legitimate sites rarely do.",
                    Severity.MEDIUM, 14));
        }

        String bodyText = doc.body() != null ? doc.body().text().toLowerCase() : "";
        if ((bodyText.contains("your computer") || bodyText.contains("your device"))
                && (bodyText.contains("virus") || bodyText.contains("infected") || bodyText.contains("hacked"))
                && (bodyText.contains("call ") || bodyText.contains("support"))) {
            out.add(signal("Fake security warning",
                    "The page displays a fake 'your device is infected' message to scare you into calling a number or installing software.",
                    Severity.MEDIUM, 18));
        }
        return out;
    }
}
