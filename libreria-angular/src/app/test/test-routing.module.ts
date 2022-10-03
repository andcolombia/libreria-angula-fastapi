import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { AuthGuard } from '../shared/auth/auth.guard';
import { PageComponent } from './page/page.component';

const routes: Routes = [];


let FLIGHT_BOOKING_ROUTES: Routes = [
  {
    path: 'page',
    component: PageComponent,
    canActivate: [AuthGuard]
  }
];

export let TestRoutingModule = RouterModule.forChild(
  FLIGHT_BOOKING_ROUTES
);

