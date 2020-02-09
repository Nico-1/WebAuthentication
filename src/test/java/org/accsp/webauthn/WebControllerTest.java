package org.accsp.webauthn;

import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.junit.runner.RunWith;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import java.nio.file.Files;
import java.nio.file.Paths;


@RunWith(SpringRunner.class)
@WebMvcTest(WebController.class)

public class WebControllerTest {

    @Autowired
    private MockMvc mvc;
    private String auth_request, auth_response, reg_request, reg_response;

    @Before
    public void setUp() throws Exception {

        auth_request = new String(Files.readAllBytes(Paths.get("src/test/resources/authenticate_sample_request.json")));
        auth_response = new String(Files.readAllBytes(Paths.get("src/test/resources/authenticate_sample_result.json")));
        reg_request = new String(Files.readAllBytes(Paths.get("src/test/resources/registration_sample_request.json")));
        reg_response = new String(Files.readAllBytes(Paths.get("src/test/resources/registration_sample_result.json")));

    }

    @Test
    public void greeting() throws Exception {
        mvc.perform(get("/status")).andDo(print()).andExpect(status().isOk());

    }

    @Test
    public void challengeRequest() throws Exception {

	    mvc.perform(get("/challenge")).andDo(print()).andExpect(status().isOk());

    }

    @Test
    public void authenticate() throws Exception {

        mvc.perform( post("/authenticate")
                .contentType(MediaType.APPLICATION_JSON)
                .content(auth_request)
                .accept(MediaType.APPLICATION_JSON)).andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    public void newRegistration() throws  Exception{

        mvc.perform( post("/registration")
                .contentType(MediaType.APPLICATION_JSON)
                .content(reg_request)
                .accept(MediaType.APPLICATION_JSON)).andDo(print())
                .andExpect(status().isOk());



    }
}