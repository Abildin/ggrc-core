/*
  Copyright (C) 2018 Google Inc.
  Licensed under http://www.apache.org/licenses/LICENSE-2.0 <see LICENSE file>
*/

import {ApprovalWorkflow as Model} from '../modals/approval-workflow-modal';
import * as aclUtils from '../../plugins/utils/acl-utils';
import {REFRESH_APPROVAL} from '../../events/eventTypes';
import Workflow from '../../models/business-models/workflow';
import TaskGroup from '../../models/business-models/task-group';
import TaskGroupTask from '../../models/business-models/task-group-task';
import Cycle from '../../models/business-models/cycle';
import TaskGroupObject from '../../models/join-models/task-group-object';

describe('ApprovalWorkflow', () => {
  describe('save() method', () => {
    let method;
    let originalObject;
    let awsDfd;
    let userOldValue;
    let currentUser;
    let assigneeRole;
    let wfAdminRole;
    let awBinding;
    let instance;

    beforeAll(() => {
      assigneeRole = {
        object_type: 'TaskGroupTask',
        name: 'Task Assignees',
        id: -10,
      };
      wfAdminRole = {
        object_type: 'Workflow',
        name: 'Admin',
        id: -12,
      };
      currentUser = new can.Map({
        email: 'test@example.com',
        name: 'Test User',
        id: -11,
      });

      userOldValue = GGRC.current_user;
      GGRC.current_user = currentUser;
    });

    afterAll(() => {
      GGRC.current_user = userOldValue;
    });

    beforeEach(() => {
      awsDfd = new can.Deferred();
      awBinding = {
        refresh_list: jasmine.createSpy().and.returnValue(awsDfd),
      };
      originalObject = {
        get_binding: jasmine.createSpy().and.returnValue(awBinding),
        refresh: jasmine.createSpy(),
      };

      instance = new Model({
        original_object: originalObject,
        contact: currentUser,
      });
      spyOn(instance.original_object, 'reify');
      spyOn(instance.original_object, 'dispatch');
      spyOn(aclUtils, 'getRole').and.returnValues(assigneeRole, wfAdminRole);

      method = Model.prototype.save.bind(instance);
    });

    describe('no approval Workflow', () => {
      let saveWfDfd;
      let saveTgDfd;
      let saveTgtDfd;
      let saveTgoDfd;
      let saveCycleDfd;

      beforeEach(() => {
        saveWfDfd = new can.Deferred();
        saveTgDfd = new can.Deferred();
        saveTgtDfd = new can.Deferred();
        saveTgoDfd = new can.Deferred();
        saveCycleDfd = new can.Deferred();

        spyOn(Workflow, 'newInstance')
          .and.returnValue({
            save: jasmine.createSpy().and.returnValue(saveWfDfd),
          });
        spyOn(TaskGroup, 'newInstance')
          .and.returnValue({
            save: jasmine.createSpy().and.returnValue(saveTgDfd),
          });
        spyOn(TaskGroupTask, 'newInstance')
          .and.returnValue({
            save: jasmine.createSpy().and.returnValue(saveTgDfd),
          });
        spyOn(TaskGroupObject, 'newInstance')
          .and.returnValue({
            save: jasmine.createSpy().and.returnValue(saveTgoDfd),
          });
        spyOn(Cycle, 'newInstance')
          .and.returnValue({
            save: jasmine.createSpy().and.returnValue(saveCycleDfd),
          });

        method();
        awsDfd.resolve([]);
      });

      it('creates an appropriate Workflow', () => {
        expect(Workflow.newInstance).toHaveBeenCalledWith({
          access_control_list: [{
            ac_role_id: wfAdminRole.id,
            person: {
              id: currentUser.id,
              type: 'Person',
            },
          }],
          unit: null,
          status: 'Active',
          title: jasmine.any(String),
          is_verification_needed: true,
          object_approval: true,
          notify_on_change: true,
          notify_custom_message: jasmine.any(String),
          context: undefined,
        });
      });

      it('creates an appropriate TaskGroup', () => {
        const wf = {};

        saveWfDfd.resolve(wf);

        expect(TaskGroup.newInstance).toHaveBeenCalledWith({
          workflow: wf,
          title: jasmine.any(String),
          contact: currentUser,
          context: undefined,
        });
      });

      it('creates an appropriate TaskGroupTask', () => {
        const wf = {};
        const tg = {};

        saveWfDfd.resolve(wf);
        saveTgDfd.resolve(tg);

        expect(TaskGroupTask.newInstance).toHaveBeenCalledWith({
          task_group: tg,
          start_date: jasmine.any(String),
          end_date: undefined,
          object_approval: true,
          access_control_list: [{
            ac_role_id: assigneeRole.id,
            person: {
              id: currentUser.id,
              type: 'Person',
            },
          }],
          context: undefined,
          task_type: 'text',
          title: jasmine.any(String),
        });
      });

      it('creates an appropriate TaskGroupObject', () => {
        const tg = {};
        const wf = new can.Map({
          context: {},
        });

        saveWfDfd.resolve(wf);
        saveTgDfd.resolve(tg);

        expect(TaskGroupObject.newInstance).toHaveBeenCalledWith({
          task_group: tg,
          object: jasmine.any(Object),
          context: wf.context,
        });
      });

      it('creates an appropriate Cycle', () => {
        const tg = {};
        const wf = {
          context: {},
        };

        saveWfDfd.resolve(wf);
        saveTgDfd.resolve(tg);
        saveTgtDfd.resolve({});
        saveTgoDfd.resolve({});

        expect(Cycle.newInstance).toHaveBeenCalledWith({
          workflow: wf,
          autogenerate: true,
          context: wf.context,
        });
      });

      it('reloads approval mapping binding object', () => {
        const tg = {};
        const wf = {
          context: {},
        };

        saveWfDfd.resolve(wf);
        saveTgDfd.resolve(tg);
        saveTgtDfd.resolve();
        saveTgoDfd.resolve();
        saveCycleDfd.resolve();

        expect(originalObject.get_binding).toHaveBeenCalled();
      });
    });

    describe('couple of approval Workflows', () => {
      let aws;
      let tgt;
      let tg;
      let saveTgDfd;
      let saveTgtDfd;
      let refreshTgtDfd;
      let saveCycleDfd;
      let awInstance;

      beforeEach(() => {
        saveTgDfd = can.Deferred();
        saveTgtDfd = can.Deferred();
        refreshTgtDfd = can.Deferred();
        saveCycleDfd = can.Deferred();

        tgt = new can.Map({
          refresh: null,
          save: null,
        });
        spyOn(tgt, 'refresh').and.returnValue(refreshTgtDfd);
        spyOn(tgt, 'save').and.returnValue(saveTgtDfd);

        tg = new can.Map({
          task_group_tasks: {
            reify: null,
          },
          save: null,
          refresh: null,
        });
        spyOn(tg, 'refresh').and.returnValue(tg);
        spyOn(tg, 'save').and.returnValue(saveTgDfd);
        spyOn(tg.task_group_tasks, 'reify').and.returnValue([tgt]);

        awInstance = {
          refresh: null,
          task_groups: {
            reify: jasmine.createSpy().and.returnValue([tg]),
          },
        };
        spyOn(awInstance, 'refresh').and.returnValue(awInstance);

        aws = [{
          instance: awInstance,
        }, {
          instance: {
            refresh: jasmine.createSpy(),
          },
        }];

        spyOn(Cycle, 'newInstance')
          .and.returnValue({
            save: jasmine.createSpy().and.returnValue(saveCycleDfd),
          });

        method();
        awsDfd.resolve(aws);
      });

      it('refreshes first Approval WF and TGs only', () => {
        expect(aws[0].instance.refresh).toHaveBeenCalled();
        expect(aws[0].instance.task_groups.reify).toHaveBeenCalled();
        expect(tg.refresh).toHaveBeenCalled();
        expect(aws[1].instance.refresh).not.toHaveBeenCalled();
      });

      it('updates contact for TGs', () => {
        expect(tg.attr('contact')).toEqual(currentUser);
      });

      it('updates TGs contact', () => {
        expect(tg.attr('contact')).toEqual(currentUser);
      });

      it('updates TGTs ACL', () => {
        saveTgDfd.resolve(tg);
        refreshTgtDfd.resolve(tgt);

        expect(tgt.attr('access_control_list.0.ac_role_id'))
          .toEqual(assigneeRole.id);
        expect(tgt.attr('access_control_list.0.person.id'))
          .toEqual(currentUser.id);
        expect(tgt.attr('access_control_list.0.person.type'))
          .toEqual('Person');
      });

      it('creates an appropriate Cycle', () => {
        saveTgDfd.resolve(tg);
        refreshTgtDfd.resolve(tgt);
        saveTgtDfd.resolve();

        expect(Cycle.newInstance).toHaveBeenCalledWith({
          workflow: awInstance,
          autogenerate: true,
          context: undefined,
        });
      });

      it('dispatches event to reload approval tasks', () => {
        saveTgDfd.resolve(tg);
        refreshTgtDfd.resolve(tgt);
        saveTgtDfd.resolve();
        saveCycleDfd.resolve();

        expect(instance.original_object.dispatch)
          .toHaveBeenCalledWith(REFRESH_APPROVAL);
      });
    });
  });
});
