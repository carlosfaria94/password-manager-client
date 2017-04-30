package pt.ulisboa.tecnico.meic.sec.lib;

import com.google.gson.Gson;
import okhttp3.*;

import java.io.IOException;

/**
 * Methods to interact with the server via a REST service
 */
public class SingleServerCalls {

    private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");

    private OkHttpClient client = new OkHttpClient();
    private String apiBaseUrl;
    private Gson json = new Gson();

    SingleServerCalls() {
        apiBaseUrl = "http://localhost:3001";
    }

    SingleServerCalls(int port) {
        this.apiBaseUrl = "http://localhost:" + port;
    }

    /**
     * Register user in the server
     *
     * @param user - User
     * @return User - null when user is not successful registered
     * @throws IOException - when remote server fails to respond
     */
    public User register(User user) throws IOException {
        RequestBody body = RequestBody.create(JSON, json.toJson(user));
        Request request = new Request.Builder()
                .url(apiBaseUrl + "/")
                .post(body)
                .build();
        Response response = client.newCall(request).execute();

        if (response.isSuccessful()) {
            //System.out.println("User successful registered: " + newUser.toString());
            return json.fromJson(response.body().string(), User.class);
        } else {
            switch (response.code()) {
                case 409:
                    //System.out.println("User already registered.");
                    break;
                case 500:
                    //System.out.println("User not registered. Internal Server error.");
                    break;
                default:
                    //System.out.println("User not registered.");
                    break;
            }
            return null;
        }
    }

    /**
     * Create a new password in server or update
     *
     * @param pwd - Password
     * @return Password
     * @throws IOException - when remote server fails to respond
     */
    public Password putPassword(Password pwd) throws IOException {
        //System.out.println(pwd);
        RequestBody body = RequestBody.create(JSON, json.toJson(pwd));
        Request request = new Request.Builder()
                .url(apiBaseUrl + "/password")
                .put(body)
                .build();
        Response response = client.newCall(request).execute();

        if (response.isSuccessful()) {
            //System.out.println("Password successful registered: " + newPassword.toString());
            return json.fromJson(response.body().string(), Password.class);
        } else {
            //System.out.println("Password not registered. HTTP Code: " + response.code());
            return null;
        }
    }

    public Password retrievePassword(Password pwd) throws IOException {
        String input = json.toJson(pwd);

        RequestBody body = RequestBody.create(JSON, input);
        Request request = new Request.Builder()
                .url(apiBaseUrl + "/retrievePassword")
                .post(body)
                .build();
        Response response = client.newCall(request).execute();

        if (response.isSuccessful()) {
            //System.out.println("Password successful retrieved: " + pwdRetrieved.toString());
            return json.fromJson(response.body().string(), Password.class);
        } else {
            //System.out.println("Password not retrieved. HTTP Code: " + response.code());
            return null;
        }
    }
}
