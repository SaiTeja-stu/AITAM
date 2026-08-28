package com.cybershield.engine.policies.web;

import com.cybershield.domain.ContentType;
import com.cybershield.domain.Severity;
import com.cybershield.domain.Signal;
import com.cybershield.engine.AbstractPolicy;
import com.cybershield.engine.PolicyContext;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** WEB-01/02: password field whose form submits to a different domain, or over http. */
@Component
public class LoginFormPolicy extends AbstractPolicy {

    public LoginFormPolicy() {
        super("WEB-01", Set.of(ContentType.WEBPAGE, ContentType.URL));
    }

    @Override
    protected List<Signal> doEvaluate(PolicyContext ctx) {
        if (ctx.html().isBlank()) return List.of();
        List<Signal> out = new ArrayList<>();
        String pageHost = ctx.primaryUrl().map(u -> u.host()).orElse("");
        Document doc = Jsoup.parse(ctx.html());

        for (Element form : doc.select("form")) {
            boolean hasPassword = !form.select("input[type=password]").isEmpty();
            if (!hasPassword) continue;

            String action = form.attr("abs:action");
            if (action.isBlank()) action = form.attr("action");

            if (action.startsWith("http://")) {
                out.add(signal("Password sent without encryption",
                        "A login form on this page submits your password over an unencrypted (http) connection.",
                        Severity.HIGH, 28));
            }
            String actionHost = hostOf(action);
            if (!actionHost.isBlank() && !pageHost.isBlank()
                    && !sameSite(actionHost, pageHost)) {
                out.add(signal("Login form posts to another domain",
                        "The password form sends your credentials to '" + actionHost
                                + "', which is different from the site you are visiting ('" + pageHost + "').",
                        Severity.CRITICAL, 50));
            }
        }
        return out;
    }

    private String hostOf(String url) {
        try {
            if (url == null || url.isBlank()) return "";
            if (url.startsWith("/") || !url.contains("://")) return "";
            return java.net.URI.create(url).getHost() == null ? "" : java.net.URI.create(url).getHost().toLowerCase();
        } catch (RuntimeException e) {
            return "";
        }
    }

    private boolean sameSite(String a, String b) {
        return reg(a).equals(reg(b));
    }

    private String reg(String host) {
        String[] p = host.split("\\.");
        return p.length <= 2 ? host : p[p.length - 2] + "." + p[p.length - 1];
    }
}
