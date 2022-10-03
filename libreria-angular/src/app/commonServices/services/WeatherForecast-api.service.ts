import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from 'src/environments/environment';
import { WeatherForecast } from '../model/WeatherForecast';
import { catchError, map, share } from 'rxjs/operators';

@Injectable({
    providedIn: 'root'
})
export class WeatherForecastApiService {
    private baseUrl = environment.apiBaseUrl;

    constructor(private http: HttpClient) { }

    Get(accessToken: string): Observable<WeatherForecast[]> {

        const headers = { 'Authorization': `Bearer ${accessToken}` };

        return this.http
            .get<WeatherForecast[]>(`${this.baseUrl}/api/private`, { headers })
            .pipe(catchError(err => {
                throw err;
            }));
    }
}
