// config/auth.js

// expose our config directly to our application using module.exports
module.exports = {
  facebookAuth: {
    clientID: "your-secret-clientID-here", // your App ID
    clientSecret: "your-client-secret-here", // your App Secret
    callbackURL: "http://localhost:8080/auth/facebook/callback",
    profileURL:
      "https://graph.facebook.com/v2.5/me?fields=first_name,last_name,email",
    profileFields: ["id", "email", "name"] // For requesting permissions from Facebook API
  },

  twitterAuth: {
    consumerKey: "your-consumer-key-here",
    consumerSecret: "your-client-secret-here",
    callbackURL: "http://localhost:8080/auth/twitter/callback"
  },

  googleAuth: {
    clientID: "137506357468-vfgj0fgm62qr48pc7ths92lf47tgc1he.apps.googleusercontent.com",
    clientSecret: "R_MmL9qH3Ezh0waF5wDYE_Bx",
    callbackURL: "http://localhost:8080/auth/google/callback"
  },

  jwt: {
    key: "somecomplextjwtkeygoeshere"
  }
};
