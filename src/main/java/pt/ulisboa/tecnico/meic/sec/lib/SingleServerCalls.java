package pt.ulisboa.tecnico.meic.sec.lib;

import com.google.gson.Gson;
import okhttp3.*;
import pt.ulisboa.tecnico.meic.sec.lib.exception.RemoteServerInvalidResponseException;

import java.io.IOException;

/**
 * Methods to interact with the server via a REST service
 */
public class SingleServerCalls {

    private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");

    private OkHttpClient client = new OkHttpClient();
    private String apiBaseUrl;
    private Gson json = new Gson();

    public SingleServerCalls() {
        apiBaseUrl = "http://localhost:3001";
    }

    public SingleServerCalls(int port) {
        this.apiBaseUrl = "http://localhost:" + port;
    }

    /**
     * Register user in the server
     *
     * @param user
     * @return - null when user is not successful registered
     * @throws IOException
     */
    public User register(User user) throws IOException, RemoteServerInvalidResponseException {
        RequestBody body = RequestBody.create(JSON, json.toJson(user));
        Request request = new Request.Builder()
                .url(apiBaseUrl + "/")
                .post(body)
                .build();
        Response response = client.newCall(request).execute();

        if (response.isSuccessful()) {
            User newUser = json.fromJson(response.body().string(), User.class);
            System.out.println("User successful registered: " + newUser.toString());
            return newUser;
        } else {
            switch (response.code()) {
                case 409:
                    System.out.println("User already registered.");
                    break;
                case 500:
                    System.out.println("User not registered. Internal Server error.");
                    break;
                default:
                    System.out.println("User not registered.");
                    break;
            }
            return null;
        }
    }

    /**
     * Create a new password in server or update
     *
     * @param pwd
     * @return
     * @throws IOException
     */
    public Password putPassword(Password pwd) throws IOException, RemoteServerInvalidResponseException {
        System.out.println(pwd);
        RequestBody body = RequestBody.create(JSON, json.toJson(pwd));
        Request request = new Request.Builder()
                .url(apiBaseUrl + "/password")
                .put(body)
                .build();
        Response response = client.newCall(request).execute();

        if (response.isSuccessful()) {
            Password newPassword = json.fromJson(response.body().string(), Password.class);
            System.out.println("Password successful registered: " + newPassword.toString());
            return newPassword;
        } else {
            System.out.println("Password not registered. HTTP Code: " + response.code());
            return null;
        }
    }

    public Password retrievePassword(Password pwd) throws IOException, RemoteServerInvalidResponseException {
        String input = json.toJson(pwd);

        RequestBody body = RequestBody.create(JSON, input);
        Request request = new Request.Builder()
                .url(apiBaseUrl + "/retrievePassword")
                .post(body)
                .build();
        Response response = client.newCall(request).execute();

        if (response.isSuccessful()) {
            Password pwdRetrieved = json.fromJson(response.body().string(), Password.class);
            System.out.println("Password successful retrieved: " + pwdRetrieved.toString());
            return pwdRetrieved;
        } else {
            System.out.println("Password not retrieved. HTTP Code: " + response.code());
            return null;
        }
    }
}
