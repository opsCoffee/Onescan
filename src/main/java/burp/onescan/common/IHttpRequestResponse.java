package burp.onescan.common;

import burp.api.montoya.http.HttpService;

/**
 * 内部接口定义,避免与 Burp 旧 API 的 burp.IHttpRequestResponse 冲突
 * 此接口使用 Montoya API 的 HttpService
 * <p>
 * MIGRATE-401-B: 此接口用于迁移阶段,最终将被 Montoya API 原生类型替代
 */
public interface IHttpRequestResponse {
    byte[] getRequest();
    void setRequest(byte[] bytes);
    byte[] getResponse();
    void setResponse(byte[] bytes);
    String getComment();
    void setComment(String s);
    String getHighlight();
    void setHighlight(String s);
    HttpService getHttpService();
    void setHttpService(HttpService httpService);
}
