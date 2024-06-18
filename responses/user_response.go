package responses


type UserDataResponse struct {
    Message string    `json:"message"`
    Data    *map[string]interface{} `json:"data"`
}