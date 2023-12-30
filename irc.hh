typedef struct {
    char groupName[50];
    char requester[5];
} GroupRequest;

typedef struct {
    GroupRequest requests[10];  // Maximum of 10 pending requests
    int requestCount;
} RequestQueue;


typedef struct {
    char sender[5];
    char groupName[50];
    char message[256];  // Adjust size as needed
} GroupMessage;

typedef struct{
    unsigned char* userName;
    unsigned char* sessionKey;
} userTicket;

typedef struct userInfo{
	unsigned char* userName;
	unsigned char* pubKey;
	RequestQueue* requestQueue;
	GroupMessage messages[50];  // Maximum of 50 messages
    int messageCount;
} userInfo;

typedef struct {
    char groupName[50];
    char creator[5];  // Assuming usernames are 5 characters long
    userInfo members[10];  // Maximum of 10 members with usernames of 5 characters
    int memberCount;
} Group;


