import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';

import { TestRoutingModule } from './test-routing.module';
import { PageComponent } from './page/page.component';
import { AuthGuard } from '../shared/auth/auth.guard';


@NgModule({
  declarations: [PageComponent],
  imports: [
    CommonModule,
    TestRoutingModule
  ],
  providers:[AuthGuard]
})
export class TestModule { }
