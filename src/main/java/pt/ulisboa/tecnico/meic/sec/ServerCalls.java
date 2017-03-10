package pt.ulisboa.tecnico.meic.sec;

import com.google.gson.Gson;
import okhttp3.*;

import java.io.IOException;

/**
 * Methods to interact with the server via a REST service
 */
public class ServerCalls {

    private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    private static final String API_BASE_URL = "http://localhost:8080";

    private OkHttpClient client = new OkHttpClient();
    private Gson json = new Gson();

    /**
     * Register user in the server
     *
     * @param publicKey
     * @return - null when user is not successful registered
     * @throws IOException
     */
    public User register(User user) throws IOException {
        RequestBody body = RequestBody.create(JSON, json.toJson(user));
        Request request = new Request.Builder()
                .url(API_BASE_URL + "/")
                .post(body)
                .build();
        Response response = client.newCall(request).execute();

        if (response.isSuccessful()) {
            User newUser = json.fromJson(response.body().string(), User.class);
            System.out.println("User successful registered: " + newUser.toString());
            return newUser;
        } else {
            System.out.println("User not registered. HTTP Code: " + response.code());
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
    public Password putPassword(Password pwd) throws IOException {
        RequestBody body = RequestBody.create(JSON, json.toJson(pwd));
        Request request = new Request.Builder()
                .url(API_BASE_URL + "/password")
                .put(body)
                .build();
        Response response = client.newCall(request).execute();

        if (response.isSuccessful()) {
            Password newPassword = json.fromJson(response.body().string(), Password.class);
            //System.out.println("Password successful registered: " + newPassword.toString());
            return newPassword;
        } else {
            System.out.println("Password not registered. HTTP Code: " + response.code());
            return null;
        }
    }

    public Password retrievePassword(Password pwd) throws IOException {
        String input = json.toJson(pwd);

        RequestBody body = RequestBody.create(JSON, input);
        Request request = new Request.Builder()
                .url(API_BASE_URL + "/retrievePassword")
                .post(body)
                .build();
        Response response = client.newCall(request).execute();

        if (response.isSuccessful()) {
            Password pwdRetrieved = json.fromJson(response.body().string(), Password.class);
            //System.out.println("Password successful retrieved: " + pwdRetrieved.toString());
            return pwdRetrieved;
        } else {
            System.out.println("Password not retrieved. HTTP Code: " + response.code());
            return null;
        }
    }
}
