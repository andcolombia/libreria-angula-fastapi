import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { HomeComponent } from './home/home.component';
import { PageComponent } from './test/page/page.component';

export let APP_ROUTES: Routes =[{
  path: '',
  redirectTo: 'home',
  pathMatch: 'full'
},
{
  path: 'home',
  component: HomeComponent
},
{
  path: 'test',
  loadChildren: () =>
    import('./test/test.module').then(
      mod => mod.TestModule
    )
}
// ,
// {
//   path: '**',
//   redirectTo: 'home'
// }
];