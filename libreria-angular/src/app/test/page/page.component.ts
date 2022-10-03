import { Component, OnInit } from '@angular/core';
import { OAuthService } from 'angular-oauth2-oidc';
import { WeatherForecast } from 'src/app/commonServices/model/WeatherForecast';
import { WeatherForecastApiService } from 'src/app/commonServices/services/WeatherForecast-api.service';

@Component({
  selector: 'app-page',
  templateUrl: './page.component.html',
  styleUrls: ['./page.component.css']
})
export class PageComponent implements OnInit {

  constructor(
    private _weatherForecastApiService: WeatherForecastApiService,
    private oauthService: OAuthService
  ) { }

  ngOnInit(): void {
    this.test();
  }

  listaWeatherForecast = new Array<WeatherForecast>();

  test() {

    this._weatherForecastApiService.Get(this.oauthService.getAccessToken()).subscribe((data) => {
      debugger;
        this.listaWeatherForecast = data;
    });
  }

}
