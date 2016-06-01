package com.example;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.Arrays;
import javax.security.auth.Subject;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import alluxio.Configuration;
import alluxio.shell.AlluxioShell;
import net.sourceforge.spnego.SpnegoLogonInfo;
import net.sourceforge.spnego.SpnegoPrincipal;

/**
 * Hello Servlet that is intended to be used in combination with the SpnegoHttpFilter.
 * It shows how single sign on (SSO) can be achieved using SPNEGO, and, if available,
 * how to read the group SIDs (Active Directory/Samba4 issued Kerberos tickets).
 *
 * All complexities are encapsulated by the filter, so this file shows simply how
 * to get to the data. If you want to learn about the details involved to achieve
 * all this beauty, please check out: ManualSpnegoNegotiateServlet, which basically
 * does the same thing, but with all implementation details exposed.
 *
 * @author mtoele
 */
public class HelloSpnegoServlet extends HttpServlet
{

	protected static final String ALLUXIO_MASTER_HOSTNAME = "alluxio.master.hostname";
	protected static final String ALLUXIO_MASTER_PORT = "alluxio.master.port";

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
    {
        response.setContentType("text/html");
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().println("<h1>SPNEGO via ServletFilter Hello Servlet</h1>");
		response.getWriter().println("<pre>");

		Principal principal = request.getUserPrincipal();
        response.getWriter().println("Hello, " + principal);

		if(principal instanceof SpnegoPrincipal) {
			SpnegoPrincipal spnegoPrincipal = (SpnegoPrincipal)principal;
			SpnegoLogonInfo logonInfo = spnegoPrincipal.getLogonInfo();
			if(logonInfo != null) {
				String[] groupSIDs = logonInfo.getGroupSids();

				Subject subject = new Subject();
				subject.getPrincipals().add(spnegoPrincipal);
				subject.getPrivateCredentials().add(logonInfo);
				
				Subject.doAs(subject, new PrivilegedAction<String>() {
					public String run() {

						System.setProperty(ALLUXIO_MASTER_HOSTNAME, "localhost");
						System.setProperty(ALLUXIO_MASTER_PORT, "19998");

						ByteArrayOutputStream baos = new ByteArrayOutputStream();
						PrintStream ps = new PrintStream(baos);
						PrintStream old = System.out;

						System.setOut(ps);

						AlluxioShell fs = new AlluxioShell(new Configuration());
						fs.run("ls", "/");

						System.out.flush();
						System.setOut(old);

						return baos.toString();
					}
				});
				

				response.getWriter().println("Found group SIDs: " + Arrays.toString(groupSIDs));
			} else {
				response.getWriter().println("No logon info available for principal.");
			}
		}

		response.getWriter().println("Authenticated.");

		response.getWriter().println("</pre>");
    }
}

